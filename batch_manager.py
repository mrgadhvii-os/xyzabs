import os
import json
import datetime
import uuid
from pathlib import Path

class BatchManager:
    def __init__(self):
        self.batches_dir = "data/batches"
        self.ensure_directories_exist()
        self.current_batch = None
        self.current_batch_id = None

    def ensure_directories_exist(self):
        """Ensure that necessary directories exist"""
        Path(self.batches_dir).mkdir(parents=True, exist_ok=True)

    def list_batches(self):
        """List all available batches"""
        batch_files = [f for f in os.listdir(self.batches_dir) if f.endswith('.json') and f != 'batch_data.json']
        batches = []
        
        for batch_file in batch_files:
            batch_id = os.path.splitext(batch_file)[0]
            try:
                with open(os.path.join(self.batches_dir, batch_file), 'r', encoding='utf-8', errors='ignore') as f:
                    batch_data = json.load(f)
                    batch_name = batch_data.get('name', batch_data.get('batch_info', {}).get('name', 'Untitled'))
                    batches.append({
                        'id': batch_id,
                        'name': batch_name,
                        'file': batch_file
                    })
            except Exception as e:
                print(f"Error loading batch {batch_file}: {e}")
                
        return batches

    def create_batch(self, name, batch_type="Regular", year=None):
        """Create a new batch with the given name"""
        if not year:
            year = datetime.datetime.now().strftime("%Y")
            
        created_at = datetime.datetime.now().strftime("%Y-%m-%d")
        
        batch_id = str(uuid.uuid4())[:8]
        
        # Create batch structure following the demov2.json format
        self.current_batch = {
            "name": name,
            "type": batch_type,
            "year": year,
            "created_at": created_at,
            "subjects": {}
        }
        
        self.current_batch_id = batch_id
        
        # Save the batch to file
        self.save_batch()
        
        return batch_id

    def load_batch(self, batch_id):
        """Load a batch by its ID"""
        batch_file = os.path.join(self.batches_dir, f"{batch_id}.json")
        
        if not os.path.exists(batch_file):
            print(f"Batch with ID {batch_id} not found.")
            return False
            
        try:
            with open(batch_file, 'r', encoding='utf-8', errors='ignore') as f:
                self.current_batch = json.load(f)
                self.current_batch_id = batch_id
                return True
        except Exception as e:
            print(f"Error loading batch: {e}")
            return False

    def save_batch(self):
        """Save the current batch to file"""
        if not self.current_batch or not self.current_batch_id:
            print("No batch to save.")
            return False
            
        batch_file = os.path.join(self.batches_dir, f"{self.current_batch_id}.json")
        
        try:
            with open(batch_file, 'w', encoding='utf-8') as f:
                json.dump(self.current_batch, f, indent=2)
            print(f"Batch saved to {batch_file}")
            return True
        except Exception as e:
            print(f"Error saving batch: {e}")
            return False

    def add_subject(self, subject_name, icon=None):
        """Add a subject to the current batch"""
        if not self.current_batch:
            print("No batch loaded.")
            return False
            
        if not icon:
            icon = subject_name.lower()
            
        # Check if subject already exists
        if subject_name.lower() in [s.lower() for s in self.current_batch["subjects"]]:
            print(f"Subject {subject_name} already exists.")
            return False
            
        # Add subject to batch
        subject_key = subject_name.lower()
        self.current_batch["subjects"][subject_key] = {
            "name": subject_name,
            "icon": icon,
            "content": []
        }
        
        self.save_batch()
        return True

    def add_chapter_content(self, subject_key, title, content_type, url, chapter_name, chapter_number=None):
        """Add content to a chapter in a subject"""
        if not self.current_batch:
            print("No batch loaded.")
            return False
            
        if subject_key not in self.current_batch["subjects"]:
            print(f"Subject {subject_key} not found.")
            return False
            
        if not chapter_number:
            # Find highest chapter number and increment
            chapter_numbers = []
            for content in self.current_batch["subjects"][subject_key]["content"]:
                if "chapter" in content and "number" in content["chapter"]:
                    chapter_numbers.append(content["chapter"]["number"])
            
            chapter_number = max(chapter_numbers, default=0) + 1
            
        content_item = {
            "title": title,
            "type": content_type,
            "url": url,
            "thumbnail": self.get_default_thumbnail(content_type),
            "chapter": {
                "name": chapter_name,
                "number": chapter_number
            },
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d")
        }
        
        # For videos, extract video_data
        if content_type == "video" and "encrypted-" in url:
            try:
                # Parse the URL format: https://appx-transcoded-videos.livelearn.in/videos/firephysics-data/1307760-1729251999/encrypted-72aa5f/360p/encrypted.mkv*1024838
                url_parts = url.split('/')
                file_part = url_parts[-1]
                hash_part = url_parts[-3].replace('encrypted-', '')
                
                id_part = url_parts[-4]
                key_part = file_part.split('*')[-1] if '*' in file_part else ""
                
                content_item["video_data"] = {
                    "id": id_part,
                    "hash": hash_part,
                    "key": key_part
                }
            except Exception as e:
                print(f"Warning: Could not parse video URL: {e}")
                
        # Add the content item to the subject
        self.current_batch["subjects"][subject_key]["content"].append(content_item)
        
        self.save_batch()
        return True
        
    def get_default_thumbnail(self, content_type):
        """Get default thumbnail based on content type"""
        if content_type == "video":
            return "https://img.classx.co.in/thumb/default-video.jpg"
        elif content_type == "pdf":
            return "/static/images/pdf_thumbnail.svg"
        elif content_type == "youtube":
            return "https://img.youtube.com/vi/default/maxresdefault.jpg"
        else:
            return "https://img.classx.co.in/thumb/default-content.jpg"

def main():
    manager = BatchManager()
    
    while True:
        print("\n===== Batch Manager =====")
        print("1. Create Batch")
        print("2. Find Batch")
        print("3. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            # Create Batch
            batch_name = input("Enter batch name: ")
            batch_type = input("Enter batch type (default: Regular): ") or "Regular"
            year = input("Enter year (default: current year): ") or datetime.datetime.now().strftime("%Y")
            
            batch_id = manager.create_batch(batch_name, batch_type, year)
            print(f"Batch created with ID: {batch_id}")
            
            manage_batch(manager)
            
        elif choice == "2":
            # Find Batch
            batches = manager.list_batches()
            
            if not batches:
                print("No batches found.")
                continue
                
            print("\nAvailable Batches:")
            for i, batch in enumerate(batches, 1):
                print(f"{i}. {batch['name']} (ID: {batch['id']})")
                
            batch_choice = input("Enter batch number to load (or 0 to cancel): ")
            
            if batch_choice == "0" or not batch_choice:
                continue
                
            try:
                batch_index = int(batch_choice) - 1
                selected_batch = batches[batch_index]
                
                if manager.load_batch(selected_batch["id"]):
                    print(f"Loaded batch: {selected_batch['name']}")
                    manage_batch(manager)
            except (ValueError, IndexError):
                print("Invalid batch number.")
                
        elif choice == "3":
            # Exit
            print("Exiting...")
            break
            
        else:
            print("Invalid choice. Please try again.")

def manage_batch(manager):
    """Manage a loaded batch"""
    while True:
        print("\n===== Batch Management =====")
        print(f"Current Batch: {manager.current_batch['name']}")
        print("1. Add Subject")
        print("2. Add Chapter Content")
        print("3. View Batch Structure")
        print("4. Back to Main Menu")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            # Add Subject
            subject_name = input("Enter subject name: ")
            subject_icon = input("Enter subject icon (default: subject name): ") or subject_name.lower()
            
            if manager.add_subject(subject_name, subject_icon):
                print(f"Subject {subject_name} added successfully.")
                
        elif choice == "2":
            # Add Chapter Content
            subjects = list(manager.current_batch["subjects"].keys())
            
            if not subjects:
                print("No subjects found. Please add a subject first.")
                continue
                
            print("\nAvailable Subjects:")
            for i, subject in enumerate(subjects, 1):
                subject_data = manager.current_batch["subjects"][subject]
                print(f"{i}. {subject_data['name']}")
                
            subject_choice = input("Enter subject number: ")
            
            try:
                subject_index = int(subject_choice) - 1
                selected_subject = subjects[subject_index]
                
                # Get chapter info
                chapter_name = input("Enter chapter name: ")
                
                # Get content info
                title = input("Enter content title: ")
                
                content_types = ["video", "pdf", "youtube"]
                print("Content Types:")
                for i, ctype in enumerate(content_types, 1):
                    print(f"{i}. {ctype}")
                    
                content_type_choice = input("Enter content type number: ")
                try:
                    content_type_index = int(content_type_choice) - 1
                    content_type = content_types[content_type_index]
                except (ValueError, IndexError):
                    print("Invalid content type. Using video as default.")
                    content_type = "video"
                
                if content_type == "video":
                    print("Enter video URL in format:")
                    print("https://appx-transcoded-videos.livelearn.in/videos/firephysics-data/1307760-1729251999/encrypted-72aa5f/360p/encrypted.mkv*1024838")
                    url = input("URL: ")
                elif content_type == "youtube":
                    yt_id = input("Enter YouTube video ID: ")
                    url = f"https://www.youtube.com/embed/{yt_id}"
                else:
                    url = input("Enter content URL: ")
                
                if manager.add_chapter_content(selected_subject, title, content_type, url, chapter_name):
                    print(f"Content added to subject {selected_subject}, chapter {chapter_name}")
                
            except (ValueError, IndexError):
                print("Invalid subject number.")
                
        elif choice == "3":
            # View Batch Structure
            print("\nBatch Structure:")
            print(json.dumps(manager.current_batch, indent=2))
            
        elif choice == "4":
            # Back to Main Menu
            break
            
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main() 