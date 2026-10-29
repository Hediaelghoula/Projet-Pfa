from flask import Flask, request, jsonify
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, firestore, storage, db as rtdb
from deepface import DeepFace
import cv2
import numpy as np
import tempfile
import os
import time
import logging
import gc
import cloudinary
import cloudinary.uploader
import requests
import io
# import mailer removed - using emailjs on frontend

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

PROJECT_ID = "pfa-iot-d5516"

# Initialize Firebase
try:
    if not firebase_admin._apps:
        cred = credentials.Certificate("pfa-iot-d5516-firebase-adminsdk-fbsvc-80ba406847.json")
        firebase_admin.initialize_app(cred, {
            'projectId': PROJECT_ID,
            'storageBucket': f'{PROJECT_ID}.firebasestorage.app',
            'databaseURL': f'https://{PROJECT_ID}-default-rtdb.firebaseio.com'
        })
    db = firestore.client()
    bucket = storage.bucket(f'{PROJECT_ID}.firebasestorage.app')
    logger.info(f"Firebase initialized for project: {PROJECT_ID} with RTDB")
except Exception as e:
    logger.critical(f"Failed to initialize Firebase: {e}")
    exit(1)

# Cloudinary Configuration
cloudinary.config(
  cloud_name = "dymj2efn0",
  api_key = "276784549799477",
  api_secret = "OSuVT6a8cq1a3HMImfXQ3jAJfLo"
)
logger.info("Cloudinary initialized")

app = Flask(__name__)
CORS(app)

def safe_delete(filepath):
    if not os.path.exists(filepath):
        return True
    try:
        os.remove(filepath)
        return True
    except PermissionError:
        pass
    try:
        cv2.destroyAllWindows()
        gc.collect()
        for _ in range(5):
            try:
                time.sleep(0.3)
                if os.path.exists(filepath):
                    os.remove(filepath)
                return True
            except PermissionError:
                continue
    except Exception as e:
        logger.warning(f"Safe delete failed for {filepath}: {e}")
    return False

def bytes_to_cv2(img_bytes):
    nparr = np.frombuffer(img_bytes, np.uint8)
    return cv2.imdecode(nparr, cv2.IMREAD_COLOR)

@app.route('/verify-face', methods=['POST'])
def verify_face():
    rfid_uid = request.headers.get('X-RFID-UID') or request.values.get('uid')
    if not rfid_uid:
        return jsonify({"error": "Missing UID", "access_granted": False}), 400

    if not request.data:
        return jsonify({"error": "No image data", "access_granted": False}), 400

    try:
        captured_img = bytes_to_cv2(request.data)
        if captured_img is None:
            return jsonify({"error": "Failed to decode image", "access_granted": False}), 400

        # Find user by RFID
        cards_ref = db.collection('rfid_cards').where('cardNumber', '==', rfid_uid).limit(1)
        docs = list(cards_ref.stream())
        
        if not docs:
            return jsonify({"access_granted": False, "reason": "carte_inconnue"}), 200

        card_data = docs[0].to_dict()
        user_id = card_data.get('userId')
        if not user_id:
            return jsonify({"access_granted": False, "reason": "carte_non_assignee"}), 200

        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({"access_granted": False, "reason": "utilisateur_introuvable"}), 200

        user_data = user_doc.to_dict()
        
        # --- VACATION MODE CHECK ---
        if user_data.get('vacationMode') == True:
            # Immediate rejection and alert
            captured_img_url = None
            try:
                upload_result = cloudinary.uploader.upload(io.BytesIO(request.data), folder="pfa_alerts", public_id=f"vacation_{rfid_uid}")
                captured_img_url = upload_result['secure_url']
            except: pass
            
            user_name = f"{user_data.get('prenom', '')} {user_data.get('nom', '')}"
            # Security alert email handled via frontend or just logging to security_alerts
            
            db.collection('security_alerts').add({
                'uid': rfid_uid, 'user_id': user_id, 'nom_complet': user_name,
                'access_granted': False, 'image_url': captured_img_url,
                'timestamp': firestore.SERVER_TIMESTAMP, 'datetime': time.strftime('%Y-%m-%d %H:%M:%S'),
                'type': 'mode_vacances_alerte', 'status': 'rejected'
            })
            return jsonify({"access_granted": False, "reason": "mode_vacances_actif", "url": captured_img_url}), 200
            
        photo_url = user_data.get('photoUrl') or user_data.get('imageURL')
        
        if not photo_url:
            return jsonify({"access_granted": False, "reason": "photo_reference_manquante"}), 200

        # Upload capture to Cloudinary
        captured_img_url = None
        try:
            upload_result = cloudinary.uploader.upload(
                io.BytesIO(request.data),
                folder="pfa_captures",
                public_id=rfid_uid
            )
            captured_img_url = upload_result['secure_url']
        except Exception as e:
            logger.error(f"Cloudinary upload failed: {e}")

        # Fetch reference image
        ref_bytes = None
        try:
            response = requests.get(photo_url)
            if response.status_code == 200:
                ref_bytes = response.content
        except Exception as e:
            logger.error(f"Failed to fetch reference image: {e}")

        if not ref_bytes:
            return jsonify({"error": "Failed to download reference", "access_granted": False}), 400

        ref_img = bytes_to_cv2(ref_bytes)
        
        # Verify face
        cap_path = tempfile.mktemp(suffix='.jpg')
        ref_path = tempfile.mktemp(suffix='.jpg')
        cv2.imwrite(cap_path, captured_img)
        cv2.imwrite(ref_path, ref_img)

        try:
            result = DeepFace.verify(cap_path, ref_path, model_name="VGG-Face", enforce_detection=False)
            match = result["verified"]
            
            user_name = f"{user_data.get('prenom', '')} {user_data.get('nom', '')}"
            # Security alerts are logged to Firestore/RTDB. Frontend can trigger EmailJS if needed.

            action_status = 'granted' if match else 'denied'
            current_time_str = time.strftime('%Y-%m-%d %H:%M:%S')
            current_timestamp_ms = int(time.time() * 1000)

            # 1. Log to Realtime Database using a specific key for deduplication
            event_id = f"{rfid_uid}_{current_timestamp_ms}"
            log_data = {
                'uid': rfid_uid,
                'user_name': user_name,
                'status': action_status,
                'method': 'facial_recognition',
                'timestamp': current_timestamp_ms,
                'datetime': current_time_str
            }
            
            if match:
                rtdb.reference('access_granted').child(event_id).set(log_data)
            else:
                log_data['image_url'] = captured_img_url
                rtdb.reference('access_refused').child(event_id).set(log_data)
            
            # Universal log for history table
            rtdb.reference('access_logs').child(event_id).set(log_data)

            # 2. Update Door Status in Firestore (if access granted)
            if match:
                try:
                    db.collection('doors').document('main_door').set({
                        'status': 'open',
                        'lastManualActionAt': current_timestamp_ms,
                        'datetime': current_time_str
                    }, merge=True)
                except Exception as e:
                    logger.error(f"Failed to update door status: {e}")

            # 3. Log to Security Alerts only if it was rejected or highly important
            if not match:
                db.collection('security_alerts').add({
                    'uid': rfid_uid,
                    'cardNumber': rfid_uid,
                    'user_id': user_id,
                    'nom_complet': user_name,
                    'access_granted': match,
                    'image_url': captured_img_url,
                    'timestamp': firestore.SERVER_TIMESTAMP,
                    'datetime': current_time_str,
                    'type': 'reconnaissance_faciale',
                    'status': 'rejected',
                    'location': 'Porte Principale'
                })

            # Don't send URL if recognized
            return jsonify({
                "access_granted": match,
                "reason": "visage_reconnu" if match else "visage_non_reconnu",
                "url": captured_img_url if not match else None
            }), 200
        finally:
            safe_delete(cap_path)
            safe_delete(ref_path)

    except Exception as e:
        logger.error(f"Error in /verify-face: {e}")
        return jsonify({"error": str(e), "access_granted": False}), 500

@app.route('/check-rfid', methods=['GET'])
def check_rfid():
    rfid_uid = request.args.get('uid')
    if not rfid_uid:
        return jsonify({"error": "Missing UID", "access_granted": False}), 400

    try:
        # Check if card exists in Firestore
        cards_ref = db.collection('rfid_cards').where('cardNumber', '==', rfid_uid).limit(1)
        docs = list(cards_ref.stream())

        if not docs:
            return jsonify({"access_granted": False, "reason": "carte_inconnue"}), 200

        card_data = docs[0].to_dict()
        user_id = card_data.get('userId')
        
        if not user_id:
            return jsonify({"access_granted": False, "reason": "carte_non_assignee"}), 200

        # Optional: check if user is active/not in vacation mode
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({"access_granted": False, "reason": "utilisateur_introuvable"}), 200

        user_data = user_doc.to_dict()
        user_full_name = f"{user_data.get('prenom', '')} {user_data.get('nom', '')}"
        
        if user_data.get('vacationMode') == True:
            # Log failure to RTDB
            rtdb.reference('access_logs').push({
                'uid': rfid_uid,
                'user_name': user_full_name,
                'status': 'denied',
                'method': 'rfid',
                'reason': 'mode_vacances_actif',
                'timestamp': int(time.time() * 1000),
                'datetime': time.strftime('%Y-%m-%d %H:%M:%S')
            })
            return jsonify({"access_granted": False, "reason": "mode_vacances_actif"}), 200

        # Success - User exists and is authorized (Step 1)
        # We NO LONGER log to access_logs here, to avoid showing partial access 
        # on the dashboard before facial recognition!
        # Status "granted" or "refused" will be logged by /verify-face (Step 2).

        return jsonify({
            "access_granted": True,
            "user_id": user_id,
            "name": user_full_name
        }), 200

    except Exception as e:
        logger.error(f"Error checking RFID {rfid_uid}: {e}")
        return jsonify({"error": str(e), "access_granted": False}), 500

@app.route('/upload-image', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({"error": "No image file"}), 400
    uid = request.form.get('uid', 'unknown')
    try:
        result = cloudinary.uploader.upload(request.files['image'], public_id=uid, folder="pfa_alerts")
        return jsonify({"url": result['secure_url'], "path": result['public_id']}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "OK"}), 200

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True, threaded=True)