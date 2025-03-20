import json
import os

def fix_json_encoding(input_file, output_file=None):
    """Fix encoding issues in a JSON file by reading it as binary and writing it with proper encoding."""
    if output_file is None:
        output_file = input_file
    
    try:
        # Read the file as binary
        with open(input_file, 'rb') as f:
            content = f.read()
        
        # Try to decode with different encodings
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                # Try to decode the content
                decoded = content.decode(encoding, errors='ignore')
                
                # Try to parse as JSON
                data = json.loads(decoded)
                
                # If successful, write back with proper encoding
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=True, indent=2)
                
                print(f"Successfully fixed encoding using {encoding} and saved to {output_file}")
                return True
            except Exception as e:
                print(f"Failed with encoding {encoding}: {e}")
                continue
        
        print("Failed to fix encoding with any known encoding")
        return False
    except Exception as e:
        print(f"Error fixing JSON file: {e}")
        return False

if __name__ == "__main__":
    # Fix the Mahamantra_2025.json file
    fix_json_encoding('data/batches/Mahamantra_2025.json') 