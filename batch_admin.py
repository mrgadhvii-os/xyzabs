import os
import json
import datetime
import uuid
from pathlib import Path
import sys

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.layout import Layout
    from rich.text import Text
    from rich import box
except ImportError:
    print("This script requires the 'rich' library. Installing it now...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "rich"])
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.layout import Layout
    from rich.text import Text
    from rich import box

console = Console()

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
                    year = batch_data.get('year', batch_data.get('batch_info', {}).get('year', ''))
                    batch_type = batch_data.get('type', batch_data.get('batch_info', {}).get('type', 'Regular'))
                    
                    # Count subjects and content
                    subjects = batch_data.get('subjects', {})
                    subject_count = len(subjects)
                    content_count = 0
                    
                    for subject_key, subject_data in subjects.items():
                        if isinstance(subject_data, dict) and 'content' in subject_data:
                            content_count += len(subject_data['content'])
                    
                    batches.append({
                        'id': batch_id,
                        'name': batch_name,
                        'year': year,
                        'type': batch_type,
                        'subject_count': subject_count,
                        'content_count': content_count,
                        'file': batch_file
                    })
            except Exception as e:
                console.print(f"[bold red]Error loading batch {batch_file}:[/] {e}")
                
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
            console.print(f"[bold red]Batch with ID {batch_id} not found.[/]")
            return False
            
        try:
            with open(batch_file, 'r', encoding='utf-8', errors='ignore') as f:
                self.current_batch = json.load(f)
                self.current_batch_id = batch_id
                return True
        except Exception as e:
            console.print(f"[bold red]Error loading batch:[/] {e}")
            return False

    def save_batch(self):
        """Save the current batch to file"""
        if not self.current_batch or not self.current_batch_id:
            console.print("[bold red]No batch to save.[/]")
            return False
            
        batch_file = os.path.join(self.batches_dir, f"{self.current_batch_id}.json")
        
        try:
            with open(batch_file, 'w', encoding='utf-8') as f:
                json.dump(self.current_batch, f, indent=2)
            console.print(f"[bold green]Batch saved to {batch_file}[/]")
            return True
        except Exception as e:
            console.print(f"[bold red]Error saving batch:[/] {e}")
            return False

    def add_subject(self, subject_name, icon=None):
        """Add a subject to the current batch"""
        if not self.current_batch:
            console.print("[bold red]No batch loaded.[/]")
            return False
            
        if not icon:
            icon = subject_name.lower()
            
        # Check if subject already exists
        if subject_name.lower() in [s.lower() for s in self.current_batch["subjects"]]:
            console.print(f"[bold yellow]Subject {subject_name} already exists.[/]")
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
            console.print("[bold red]No batch loaded.[/]")
            return False
            
        if subject_key not in self.current_batch["subjects"]:
            console.print(f"[bold red]Subject {subject_key} not found.[/]")
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
                console.print(f"[bold yellow]Warning: Could not parse video URL:[/] {e}")
                
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
            
    def get_subject_stats(self, subject_key):
        """Get statistics for a subject"""
        subject = self.current_batch["subjects"].get(subject_key, {})
        content_items = subject.get("content", [])
        
        stats = {
            "total": len(content_items),
            "video": 0,
            "pdf": 0,
            "youtube": 0,
            "other": 0,
            "chapters": set()
        }
        
        for item in content_items:
            content_type = item.get("type", "other")
            if content_type in stats:
                stats[content_type] += 1
            else:
                stats["other"] += 1
                
            if "chapter" in item and "name" in item["chapter"]:
                stats["chapters"].add(item["chapter"]["name"])
                
        stats["chapters"] = sorted(list(stats["chapters"]))
        
        return stats

def display_batch_list(batches):
    """Display a table of batches"""
    table = Table(title="Available Batches", box=box.ROUNDED)
    
    table.add_column("#", style="dim")
    table.add_column("Batch Name", style="bold")
    table.add_column("ID", style="dim")
    table.add_column("Year")
    table.add_column("Type")
    table.add_column("Subjects", justify="right")
    table.add_column("Content Items", justify="right")
    
    for i, batch in enumerate(batches, 1):
        table.add_row(
            str(i),
            batch["name"],
            batch["id"],
            batch["year"],
            batch["type"],
            str(batch["subject_count"]),
            str(batch["content_count"])
        )
    
    console.print(table)

def display_subject_list(manager):
    """Display a table of subjects in the current batch"""
    subjects = manager.current_batch["subjects"]
    
    table = Table(title="Subjects in Current Batch", box=box.ROUNDED)
    
    table.add_column("#", style="dim")
    table.add_column("Subject Name", style="bold")
    table.add_column("Key")
    table.add_column("Icon")
    table.add_column("Content Items", justify="right")
    table.add_column("Videos", justify="right")
    table.add_column("PDFs", justify="right")
    table.add_column("Chapters", justify="right")
    
    for i, (subject_key, subject_data) in enumerate(subjects.items(), 1):
        stats = manager.get_subject_stats(subject_key)
        
        table.add_row(
            str(i),
            subject_data.get("name", subject_key),
            subject_key,
            subject_data.get("icon", ""),
            str(stats["total"]),
            str(stats["video"]),
            str(stats["pdf"]),
            str(len(stats["chapters"]))
        )
    
    console.print(table)

def display_content_list(manager, subject_key):
    """Display a table of content items in a subject"""
    subject = manager.current_batch["subjects"].get(subject_key, {})
    content_items = subject.get("content", [])
    
    if not content_items:
        console.print("[bold yellow]No content items found in this subject.[/]")
        return
    
    table = Table(title=f"Content in {subject.get('name', subject_key)}", box=box.ROUNDED)
    
    table.add_column("#", style="dim")
    table.add_column("Title", style="bold")
    table.add_column("Type")
    table.add_column("Chapter")
    table.add_column("Created At")
    
    # Group by chapter
    chapters = {}
    for item in content_items:
        chapter_name = item.get("chapter", {}).get("name", "Other")
        if chapter_name not in chapters:
            chapters[chapter_name] = []
        chapters[chapter_name].append(item)
    
    i = 1
    for chapter_name, items in sorted(chapters.items()):
        table.add_row(f"[bold cyan]{chapter_name}[/]", "", "", "", "")
        
        for item in items:
            content_type = item.get("type", "unknown")
            type_color = {
                "video": "green",
                "pdf": "blue",
                "youtube": "red"
            }.get(content_type, "white")
            
            table.add_row(
                str(i),
                item.get("title", "Untitled"),
                f"[{type_color}]{content_type}[/]",
                item.get("chapter", {}).get("name", ""),
                item.get("created_at", "")
            )
            i += 1
    
    console.print(table)

def display_batch_header(manager):
    """Display information about the current batch"""
    batch = manager.current_batch
    
    # Count content by type
    video_count = 0
    pdf_count = 0
    other_count = 0
    
    for subject_key, subject_data in batch.get("subjects", {}).items():
        for content in subject_data.get("content", []):
            content_type = content.get("type", "")
            if content_type == "video":
                video_count += 1
            elif content_type == "pdf":
                pdf_count += 1
            else:
                other_count += 1
    
    panel = Panel(
        f"[bold]{batch.get('name')}[/] ({batch.get('year')})\n"
        f"Type: {batch.get('type')}\n"
        f"Created: {batch.get('created_at')}\n"
        f"ID: {manager.current_batch_id}\n"
        f"Subjects: {len(batch.get('subjects', {}))}\n"
        f"Content: {video_count} videos, {pdf_count} PDFs, {other_count} other",
        title="Current Batch",
        border_style="green"
    )
    
    console.print(panel)

def main():
    manager = BatchManager()
    
    console.print(Panel.fit(
        "[bold blue]Batch Manager[/]\n"
        "A tool for managing learning batch content",
        border_style="blue"
    ))
    
    while True:
        console.print("\n[bold]Main Menu[/]")
        console.print("[1] Create New Batch")
        console.print("[2] Load Existing Batch")
        console.print("[3] Exit")
        
        choice = Prompt.ask("Enter your choice", choices=["1", "2", "3"])
        
        if choice == "1":
            # Create Batch
            batch_name = Prompt.ask("Enter batch name")
            batch_type = Prompt.ask("Enter batch type", default="Regular")
            year = Prompt.ask("Enter year", default=datetime.datetime.now().strftime("%Y"))
            
            # Create batch without using spinner
            console.print("[bold green]Creating batch...[/]")
            batch_id = manager.create_batch(batch_name, batch_type, year)
            
            console.print(f"[bold green]Batch created with ID:[/] {batch_id}")
            
            # Immediately prompt to add content
            if Confirm.ask("Would you like to add subjects and content now?"):
                manage_batch(manager)
            
        elif choice == "2":
            # Find and Load Batch
            with console.status("[bold green]Loading batches...[/]"):
                batches = manager.list_batches()
            
            if not batches:
                console.print("[bold yellow]No batches found.[/]")
                if Confirm.ask("Would you like to create a new batch?"):
                    batch_name = Prompt.ask("Enter batch name")
                    batch_type = Prompt.ask("Enter batch type", default="Regular")
                    year = Prompt.ask("Enter year", default=datetime.datetime.now().strftime("%Y"))
                    
                    with console.status("[bold green]Creating batch...[/]"):
                        batch_id = manager.create_batch(batch_name, batch_type, year)
                    
                    console.print(f"[bold green]Batch created with ID:[/] {batch_id}")
                    
                    # Immediately prompt to add content
                    if Confirm.ask("Would you like to add subjects and content now?"):
                        manage_batch(manager)
                continue
                
            display_batch_list(batches)
                
            choice = Prompt.ask(
                "Enter batch number to load (or 0 to cancel)",
                default="0"
            )
            
            if choice == "0":
                continue
                
            try:
                batch_index = int(choice) - 1
                if batch_index < 0 or batch_index >= len(batches):
                    raise ValueError()
                    
                selected_batch = batches[batch_index]
                
                try:
                    # Load batch without spinner
                    console.print(f"[bold green]Loading batch {selected_batch['name']}...[/]")
                    success = manager.load_batch(selected_batch["id"])
                    
                    if success:
                        console.print(f"[bold green]Loaded batch:[/] {selected_batch['name']}")
                        manage_batch(manager)
                    else:
                        console.print(f"[bold red]Failed to load batch.[/]")
                except Exception as e:
                    console.print(f"[bold red]Error loading batch:[/] {str(e)}")
            except ValueError:
                console.print("[bold red]Invalid batch number.[/]")
                
        elif choice == "3":
            # Exit
            console.print("[bold green]Exiting...[/]")
            break

def manage_batch(manager):
    """Manage a loaded batch"""
    while True:
        console.clear()
        display_batch_header(manager)
        
        console.print("\n[bold]Batch Management[/]")
        console.print("[1] Add Subject")
        console.print("[2] Add Content to Subject")
        console.print("[3] View Batch Structure")
        console.print("[4] Back to Main Menu")
        
        choice = Prompt.ask("Enter your choice", choices=["1", "2", "3", "4"])
        
        if choice == "1":
            # Add Subject
            subject_name = Prompt.ask("Enter subject name")
            
            # Suggest a standard icon based on common subjects
            suggested_icon = subject_name.lower()
            standard_icons = {
                "physics": "physics",
                "chemistry": "chemistry", 
                "biology": "biology",
                "mathematics": "mathematics",
                "math": "mathematics",
                "english": "english",
                "history": "history",
                "geography": "geography",
                "computer": "computer",
                "programming": "code"
            }
            
            for key, icon in standard_icons.items():
                if key in subject_name.lower():
                    suggested_icon = icon
                    break
            
            subject_icon = Prompt.ask(f"Enter subject icon", default=suggested_icon)
            
            # Use a simple function call instead of status context manager
            success = manager.add_subject(subject_name, subject_icon)
            if success:
                console.print(f"[bold green]Subject {subject_name} added successfully.[/]")
                
                # Immediately prompt to add content
                if Confirm.ask("Would you like to add content to this subject now?"):
                    add_content_to_subject(manager, subject_name.lower())
                
        elif choice == "2":
            # Add Content to Subject directly
            subjects = list(manager.current_batch["subjects"].keys())
            
            if not subjects:
                console.print("[bold yellow]No subjects found. Please add a subject first.[/]")
                if Confirm.ask("Add a subject now?"):
                    subject_name = Prompt.ask("Enter subject name")
                    subject_icon = Prompt.ask("Enter subject icon", default=subject_name.lower())
                    
                    # Use direct function call instead of context manager
                    success = manager.add_subject(subject_name, subject_icon)
                    if success:
                        console.print(f"[bold green]Subject {subject_name} added successfully.[/]")
                        add_content_to_subject(manager, subject_name.lower())
                continue
            
            # Display subjects
            console.print("\n[bold]Available Subjects:[/]")
            for i, subject_key in enumerate(subjects, 1):
                subject_name = manager.current_batch["subjects"][subject_key].get("name", subject_key)
                console.print(f"[{i}] {subject_name}")
                
            subject_choice = Prompt.ask(
                "Select subject (number)",
                choices=[str(i) for i in range(1, len(subjects) + 1)]
            )
            
            try:
                subject_index = int(subject_choice) - 1
                selected_subject = subjects[subject_index]
                
                add_content_to_subject(manager, selected_subject)
                
            except (ValueError, IndexError):
                console.print("[bold red]Invalid subject number.[/]")
                
        elif choice == "3":
            # View Batch Structure
            console.print("\n[bold]Batch Structure:[/]")
            console.print_json(data=manager.current_batch)
            input("\nPress Enter to continue...")
            
        elif choice == "4":
            # Back to Main Menu
            break

def add_content_to_subject(manager, subject_key):
    """Add content to a subject"""
    subject_name = manager.current_batch["subjects"][subject_key].get("name", subject_key)
    
    console.print(f"\n[bold]Adding Content to {subject_name}[/]")
    
    # Get existing chapters for this subject
    existing_chapters = set()
    for content in manager.current_batch["subjects"][subject_key].get("content", []):
        if "chapter" in content and "name" in content["chapter"]:
            existing_chapters.add(content["chapter"]["name"])
    
    # Display existing chapters
    if existing_chapters:
        console.print("\n[bold]Existing Chapters:[/]")
        for i, chapter in enumerate(sorted(existing_chapters), 1):
            console.print(f"[{i}] {chapter}")
    
    # Get chapter info
    if existing_chapters:
        use_existing = Confirm.ask("Use an existing chapter?")
        if use_existing:
            chapter_names = sorted(list(existing_chapters))
            for i, chapter in enumerate(chapter_names, 1):
                console.print(f"[{i}] {chapter}")
                
            chapter_choice = Prompt.ask(
                "Select chapter (number)",
                choices=[str(i) for i in range(1, len(chapter_names) + 1)]
            )
            
            try:
                chapter_index = int(chapter_choice) - 1
                chapter_name = chapter_names[chapter_index]
            except (ValueError, IndexError):
                console.print("[bold red]Invalid chapter number. Creating new chapter.[/]")
                chapter_name = Prompt.ask("Enter new chapter name")
        else:
            chapter_name = Prompt.ask("Enter new chapter name")
    else:
        chapter_name = Prompt.ask("Enter chapter name")
    
    # Get bulk content items
    console.print("\n[bold]Paste Content Items[/] (one per line in format: [italic]Name:URL[/italic])")
    console.print("Example:\nPhysics Revision Live Class : 1:https://transcoded-videos-v2.classx.co.in/videos/firephysics-data/1504791-1734356869/encrypted-5a2b11/360p/encrypted.mkv*9618224")
    console.print("Physics Round 1 Que Paper:https://appx-content-v2.classx.co.in/paid_course4/2024-12-18-0.2961065930545428.pdf")
    console.print("\nPress Enter twice when finished\n")
    
    # Collect content items
    content_lines = []
    while True:
        line = input()
        if not line:
            break
        content_lines.append(line)
    
    if not content_lines:
        console.print("[bold yellow]No content items provided. Returning to subject management.[/]")
        return
    
    # Process each content item
    added_items = 0
    
    # Process without a spinner that might get stuck
    console.print("[bold green]Processing content items...[/]")
    for i, line in enumerate(content_lines):
        if ":" not in line:
            console.print(f"[bold yellow]Skipping line {i+1}, invalid format (missing ':'): {line}[/]")
            continue
            
        # Split by first colon
        title, url = line.split(":", 1)
        title = title.strip()
        url = url.strip()
        
        if not title or not url:
            console.print(f"[bold yellow]Skipping line {i+1}, missing title or URL: {line}[/]")
            continue
            
        # Auto-detect content type from URL
        content_type = "video"  # Default
        
        if ".pdf" in url.lower():
            content_type = "pdf"
        elif "youtube.com" in url.lower() or "youtu.be" in url.lower():
            content_type = "youtube"
        elif "vimeo.com" in url.lower():
            content_type = "vimeo"
        elif url.lower().endswith((".mp4", ".mkv", ".avi", ".mov")):
            content_type = "video"
        elif url.lower().endswith((".jpg", ".jpeg", ".png", ".gif")):
            content_type = "image"
        elif url.lower().endswith((".doc", ".docx")):
            content_type = "document"
        elif url.lower().endswith((".ppt", ".pptx")):
            content_type = "presentation"
        elif "encrypted" in url.lower() and "mkv" in url.lower():
            content_type = "video"
            
        # Create content item
        content_item = {
            "title": title,
            "type": content_type,
            "url": url,
            "thumbnail": manager.get_default_thumbnail(content_type),
            "chapter": {
                "name": chapter_name,
                "number": 1  # Default chapter number
            },
            "created_at": datetime.datetime.now().strftime("%Y-%m-%d")
        }
        
        # Extract video_data for compatible video URLs
        if content_type == "video" and ("encrypted" in url.lower() and "*" in url):
            try:
                # Parse the URL format: https://transcoded-videos-v2.classx.co.in/videos/firephysics-data/1504791-1734356869/encrypted-5a2b11/360p/encrypted.mkv*9618224
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
                
                console.print(f"[green]✓[/] Extracted video data from: {title}")
            except Exception as e:
                console.print(f"[bold yellow]Warning: Could not parse video URL for {title}: {e}[/]")
        
        # Add content to subject
        manager.current_batch["subjects"][subject_key]["content"].append(content_item)
        added_items += 1
        console.print(f"[green]✓[/] Added: {title}")
    
    # Save the batch
    if added_items > 0:
        # Save without a spinner
        result = manager.save_batch()
        if result:
            console.print(f"[bold green]Successfully added {added_items} content items to {subject_name}, chapter {chapter_name}[/]")
        else:
            console.print(f"[bold red]Error saving batch after adding content items.[/]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Program interrupted. Exiting...[/]")
    except Exception as e:
        console.print(f"\n[bold red]An error occurred:[/] {str(e)}")
        raise 