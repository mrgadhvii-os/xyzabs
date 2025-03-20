import firebase_admin
from firebase_admin import credentials, firestore
import os

# Firebase configuration
def initialize_firebase():
    """Initialize Firebase connection"""
    try:
        # Check if already initialized
        if not firebase_admin._apps:
            # Path to your Firebase service account JSON file
            service_account_path = 'firebase-service-account.json'
            
            if os.path.exists(service_account_path):
                cred = credentials.Certificate(service_account_path)
                firebase_admin.initialize_app(cred)
                return True
            else:
                print(f"Firebase service account file not found at {service_account_path}")
                return False
        return True
    except Exception as e:
        print(f"Error initializing Firebase: {str(e)}")
        return False

def get_firestore_db():
    """Get Firestore database instance"""
    if initialize_firebase():
        return firestore.client()
    return None

# Batch operations
def save_batch_to_firebase(batch_data):
    """Save batch data to Firebase"""
    try:
        db = get_firestore_db()
        if not db:
            return False, "Failed to connect to Firebase"
        
        # Create a new batch document
        batch_ref = db.collection('batches').document()
        batch_id = batch_ref.id
        
        # Create a response object with batch_id
        result = {"batch_id": batch_id}
        
        # Save batch data without modifying the original structure
        batch_ref.set(batch_data)
        
        return True, result
    except Exception as e:
        return False, f"Error saving batch to Firebase: {str(e)}"

def get_batches_from_firebase():
    """Get all batches from Firebase"""
    try:
        db = get_firestore_db()
        if not db:
            return False, "Failed to connect to Firebase"
        
        batches = []
        batch_docs = db.collection('batches').stream()
        
        for doc in batch_docs:
            batch_data = doc.to_dict()
            batches.append(batch_data)
        
        return True, batches
    except Exception as e:
        return False, f"Error getting batches from Firebase: {str(e)}"

def get_batch_by_id(batch_id):
    """Get a batch by ID from Firebase"""
    try:
        db = get_firestore_db()
        if not db:
            return False, "Failed to connect to Firebase"
        
        batch_doc = db.collection('batches').document(batch_id).get()
        
        if batch_doc.exists:
            # Get the batch data
            batch_data = batch_doc.to_dict()
            
            # Add batch_id to the result for reference by the application
            batch_data["batch_id"] = batch_id
            
            return True, batch_data
        else:
            return False, f"Batch with ID {batch_id} not found"
    except Exception as e:
        return False, f"Error getting batch from Firebase: {str(e)}"

def update_batch(batch_id, batch_data):
    """Update an existing batch in Firebase"""
    try:
        db = get_firestore_db()
        if not db:
            return False, "Failed to connect to Firebase"
        
        # Update batch document without adding batch_id to the main data structure
        db.collection('batches').document(batch_id).set(batch_data)
        
        return True, batch_id
    except Exception as e:
        return False, f"Error updating batch in Firebase: {str(e)}"

def delete_batch(batch_id):
    """Delete a batch from Firebase"""
    try:
        db = get_firestore_db()
        if not db:
            return False, "Failed to connect to Firebase"
        
        db.collection('batches').document(batch_id).delete()
        
        return True, "Batch deleted successfully"
    except Exception as e:
        return False, f"Error deleting batch from Firebase: {str(e)}" 