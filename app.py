from flask import Flask, Response, request, stream_with_context, render_template, abort, session, redirect, url_for, flash, jsonify, make_response, g, send_file, has_request_context
import yt_dlp
import requests
import re
import os
import json
import uuid
import time
import hashlib
import random
import string
import io
from PIL import Image, ImageDraw, ImageFont
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import firebase_admin
from firebase_admin import credentials, auth, firestore
from flask_session import Session
import tempfile
import base64
import hmac
import urllib.parse
from datetime import datetime, timedelta
import threading
import subprocess
import secrets
import zipfile
import shutil
import glob
import traceback
from flask_bcrypt import Bcrypt
from urllib.parse import quote
from flask_cors import CORS
import psutil
import ffmpeg
from cachetools import TTLCache
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Cache for storing video information to reduce repeated API calls
video_info_cache = TTLCache(maxsize=100, ttl=3600)  # Cache for 1 hour
ffmpeg_process_cache = {}  # Store ffmpeg processes

# Supported video qualities
VIDEO_QUALITIES = ["240p", "360p", "480p", "720p", "1080p"]
DEFAULT_QUALITY = "360p"

# FFmpeg installation check function
def check_ffmpeg_installation():
    """Verify FFmpeg is installed and available"""
    try:
        result = subprocess.run(['ffmpeg', '-version'], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.PIPE, 
                              text=True, 
                              check=True)
        logger.info(rf"FFmpeg installed: {result.stdout.split('\n')[0]}")
        return True
    except subprocess.CalledProcessError:
        logger.error("FFmpeg failed to run. Check installation.")
        return False
    except FileNotFoundError:
        logger.error("FFmpeg not found. Please install FFmpeg.")
        return False

# Check FFmpeg availability once at startup
ffmpeg_available = check_ffmpeg_installation()
logger.info(f"FFmpeg availability: {'Available' if ffmpeg_available else 'Not available'}")
# Function to get all available qualities for a video
def get_available_qualities(video_id, video_hash):
    """Check which qualities are available for a given video"""
    cache_key = f"{video_id}_{video_hash}_qualities"
    
    # Check if we have cached results with a longer TTL
    if cache_key in video_info_cache:
        logger.info(f"Using cached qualities for {video_id}_{video_hash}")
        return video_info_cache[cache_key]
    
    logger.info(f"Checking available qualities for {video_id}_{video_hash}")
    
    # Define the qualities to check
    qualities_to_check = VIDEO_QUALITIES
    available_qualities = []
    
    # Create base URLs for both patterns
    base_url1 = f"https://appx-transcoded-videos.livelearn.in/videos/firephysics-data/{video_id}/encrypted{video_hash}"
    base_url2 = f"https://appx-transcoded-videos.livelearn.in/videos/firephysics-data/{video_id}/encrypted-{video_hash}"
    
    # Try first pattern with a single request first (optimization)
    try:
        test_url = f"{base_url1}/360p/encrypted.mkv"
        response = requests.head(test_url, timeout=3)
        if response.status_code == 200:
            # First pattern works, check all qualities in this pattern
            for quality in qualities_to_check:
                try:
                    url = f"{base_url1}/{quality}/encrypted.mkv"
                    response = requests.head(url, timeout=3)
                    if response.status_code == 200:
                        available_qualities.append(quality)
                except:
                    pass
        else:
            # Try second pattern
            test_url = f"{base_url2}/360p/encrypted.mkv"
            response = requests.head(test_url, timeout=3)
            if response.status_code == 200:
                # Second pattern works, check all qualities in this pattern
                for quality in qualities_to_check:
                    try:
                        url = f"{base_url2}/{quality}/encrypted.mkv"
                        response = requests.head(url, timeout=3)
                        if response.status_code == 200:
                            available_qualities.append(quality)
                    except:
                        pass
    except Exception as e:
        logger.error(f"Error checking qualities: {str(e)}")
        # Continue with default approach on exception
    
    # If no qualities found through optimized approach, fall back to checking both patterns for all qualities
    if not available_qualities:
        logger.info("Falling back to comprehensive quality check")
        
        # Check first pattern for all qualities
        for quality in qualities_to_check:
            url = f"{base_url1}/{quality}/encrypted.mkv"
            try:
                response = requests.head(url, timeout=3)
                if response.status_code == 200:
                    available_qualities.append(quality)
            except:
                pass
        
        # If still no qualities, check second pattern
        if not available_qualities:
            for quality in qualities_to_check:
                url = f"{base_url2}/{quality}/encrypted.mkv"
                try:
                    response = requests.head(url, timeout=3)
                    if response.status_code == 200:
                        available_qualities.append(quality)
                except:
                    pass
    
    # Default to 360p if no qualities found
    if not available_qualities and "360p" in VIDEO_QUALITIES:
        logger.info(f"No qualities found for {video_id}_{video_hash}, defaulting to 360p")
        available_qualities.append("360p")
    
    # Sort the qualities from highest to lowest
    available_qualities = sorted(available_qualities, key=lambda q: int(q.rstrip('p')), reverse=True)
    
    # Cache the results for longer (5 minutes)
    video_info_cache[cache_key] = available_qualities
    logger.info(f"Found qualities for {video_id}_{video_hash}: {available_qualities}")
    
    return available_qualities

# Function to handle video streaming with custom decryption and fast seeking
def ffmpeg_stream_video(video_url, custom_key=None, start_time=0, quality=None):
    """
    Stream video with optimized custom decryption and seeking
    
    Args:
        video_url: URL of the encrypted video
        custom_key: Decryption key
        start_time: Start time in seconds
        quality: Desired quality (e.g. "360p", "720p")
    
    Returns:
        A generator yielding video chunks
    """
    # Parse start_time properly - ensure it's a valid number
    try:
        start_time = float(start_time)
        if start_time < 0:
            start_time = 0
    except (ValueError, TypeError):
        start_time = 0
        
    # Apply quality selection to URL if needed
    if quality and quality != DEFAULT_QUALITY:
        # Handle both URL patterns
        if '/encrypted-' in video_url:
            # Extract parts before and after the quality
            parts = re.match(r'(.*?/encrypted-[^/]+/)([^/]+)(/.*)', video_url)
            if parts:
                video_url = f"{parts.group(1)}{quality}{parts.group(3)}"
        elif '/encrypted' in video_url:
            # Extract parts before and after the quality
            parts = re.match(r'(.*?/encrypted[^/]+/)([^/]+)(/.*)', video_url)
            if parts:
                video_url = f"{parts.group(1)}{quality}{parts.group(3)}"
    
    logger.info(f"Starting optimized stream for: {video_url[:50]}... at position {start_time}s")
    
    try:
        # Get direct URL through yt-dlp (more reliable)
        direct_url, filesize = get_video_info(video_url)
        logger.info(f"Got direct URL with size: {filesize} bytes")
        
        # Skip the seek step for very small seek times
        if start_time < 0.5:
            start_time = 0
            
        # Set up ffmpeg command for proper seeking
        if start_time > 0:
            # Use ffmpeg with -ss parameter for accurate seeking
            logger.info(f"Setting up FFmpeg with seeking to {start_time} seconds")
            
            CHUNK_SIZE = 1024 * 1024 * 2
            # Create FFmpeg command with accurate seeking
            cmd = [
                'ffmpeg',
                '-ss', str(start_time),  # Seek position in seconds
                '-i', direct_url,        # Input file
                '-c', 'copy',            # Copy streams without re-encoding
                '-movflags', 'frag_keyframe+empty_moov+faststart',  # Optimize for streaming
                '-f', 'mp4',             # Force MP4 format
                '-'                      # Output to stdout
            ]
            
            # Execute ffmpeg command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=10**8  # Use large buffer
            )
            
            # Add process to active processes for cleanup
            video_info_cache["active_processes"].append(process)
            
            # Stream the output in chunks
            for chunk in iter(lambda: process.stdout.read(CHUNK_SIZE), b''):
                yield chunk
                
            # Check if process is still running and terminate if needed
            if process.poll() is None:
                process.terminate()
                try:
                    video_info_cache["active_processes"].remove(process)
                except ValueError:
                    pass
            
            return
        
        # For normal playback without seeking, use regular HTTP streaming
        # Set up HTTP headers for the request
        headers = {}
        if start_time > 0:
            headers['Range'] = f"bytes={int(start_time * 1024 * 1024)}-{filesize}"
        
        # Special handling for initial load vs seeking behavior
        use_smaller_chunks = (start_time == 0)
        
        # Initial chunk size is smaller for faster startup
        initial_chunk_size = 512 * 1024  # 512KB for fast initial loading
        normal_chunk_size = 4 * 1024 * 1024  # 4MB for continued playback
        
        # Make the request with a timeout
        session = requests.Session()
        response = session.get(direct_url, stream=True, headers=headers, timeout=10)
        
        if response.status_code not in (200, 206):
            logger.error(f"Error fetching video: HTTP {response.status_code}")
            return
        
        # Process the stream with optimized decryption
        bytes_processed = start_time * 1024 * 1024  # Track global position for decryption
        is_first_chunk = True
        chunk_count = 0
        
        # Get content length if available
        content_length = int(response.headers.get('Content-Length', '0'))
        
        # Stream with variable chunk sizes
        for chunk in response.iter_content(chunk_size=initial_chunk_size if is_first_chunk and use_smaller_chunks else normal_chunk_size):
            if not chunk:
                continue
                
            chunk_count += 1
            chunk_size = len(chunk)
            
            # Check if we need to decrypt part of this chunk
            if bytes_processed < HEADER_DECRYPTION_BYTES:
                # Decrypt using our custom XOR decryption
                chunk_array = bytearray(chunk)
                decrypt_up_to = min(HEADER_DECRYPTION_BYTES - bytes_processed, chunk_size)
                
                for i in range(decrypt_up_to):
                    index = bytes_processed + i
                    if custom_key and index < len(custom_key):
                        # XOR with corresponding key byte
                        chunk_array[i] = chunk_array[i] ^ ord(custom_key[index])
                    else:
                        # XOR with index
                        chunk_array[i] = chunk_array[i] ^ index
                
                yield bytes(chunk_array)
            else:
                # Beyond decryption header, send chunk as is
                yield chunk
            
            # Track position and switch to larger chunks after first chunk
            bytes_processed += chunk_size
            is_first_chunk = False
            
            # Log progress for initial chunks
            if chunk_count <= 3:
                percent = int((bytes_processed / content_length * 100)) if content_length > 0 else "unknown"
                logger.info(f"Streamed chunk {chunk_count}: {chunk_size/1024:.1f}KB ({percent}% of {content_length/1024/1024:.1f}MB)")
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error while streaming: {str(e)}")
        yield b''
    except Exception as e:
        logger.error(f"Streaming error: {str(e)}")
        yield b''

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key')  # You should set this in your environment
bcrypt = Bcrypt(app)
# Enable CORS for all routes
CORS(app)

# Admin password for share links management
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', "Jay@2007")

# Configure server-side session

app.config['SESSION_TYPE'] = 'filesystem'
session_dir = os.path.join(tempfile.gettempdir(), 'flask_session')

app.config['SESSION_FILE_DIR'] = session_dir
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 365 * 24 * 60 * 60  # Extend to 365 days
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'vidh_'
app.config['SESSION_COOKIE_SECURE'] = False  # Allow non-HTTPS for development
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Create session directory if it doesn't exist
os.makedirs(session_dir, exist_ok=True)

Session(app)

# Initialize Firebase Admin SDK
try:
    # Check if running on Vercel and using environment variable
    firebase_service_account = os.environ.get('FIREBASE_SERVICE_ACCOUNT')
    if firebase_service_account:
        # Parse the JSON string from environment variable
        try:
            service_account_info = json.loads(firebase_service_account)
            cred = credentials.Certificate(service_account_info)
            firebase_admin.initialize_app(cred)
            db = firestore.client()
            print("Firebase Admin SDK initialized from environment variable")
        except Exception as e:
            print(f"Error initializing Firebase from environment variable: {str(e)}")
            db = None
    # Check if service account file exists
    elif not os.path.exists('firebase-service-account.json'):
        print("Error: firebase-service-account.json not found. Please download it from Firebase Console.")
        print("1. Go to Firebase Console (https://console.firebase.google.com)")
        print("2. Select your project")
        print("3. Go to Project Settings > Service Accounts")
        print("4. Click 'Generate New Private Key'")
        print("5. Save the downloaded file as 'firebase-service-account.json' in the project root")
        db = None
    else:
        try:
            # Try to read the service account file
            with open('firebase-service-account.json', 'r') as f:
                service_account_data = json.load(f)
                print("Service account file loaded successfully")
                print(f"Project ID: {service_account_data.get('project_id', 'Not found')}")
        except json.JSONDecodeError as e:
            print(f"Error reading service account file: Invalid JSON format - {str(e)}")
            db = None
        except Exception as e:
            print(f"Error reading service account file: {str(e)}")
            db = None
        else:
            try:
                # Initialize Firebase with the service account
                cred = credentials.Certificate('firebase-service-account.json')
                firebase_admin.initialize_app(cred)
                
                # Initialize Firestore
                db = firestore.client()
                print("Firebase Admin SDK initialized successfully")
                
                # Test the connection
                try:
                    # Try a simple query to verify the connection
                    test_doc = db.collection('test').document('test').get()
                    print("Firestore connection test successful")
                except Exception as e:
                    if 'invalid_grant' in str(e) and 'Invalid JWT Signature' in str(e):
                        print("Firebase authentication failed: Invalid JWT Signature")
                        print("This might be due to:")
                        print("1. Private key format issues in the service account file")
                        print("2. System time not synchronized correctly")
                        print("3. Expired or revoked service account credentials")
                        print("Try re-downloading a new service account key from Firebase Console")
                    else:
                        print(f"Firestore connection test failed: {str(e)}")
                    db = None
            except Exception as e:
                if 'invalid_grant' in str(e) and 'Invalid JWT Signature' in str(e):
                    print("Firebase authentication failed: Invalid JWT Signature")
                    print("This might be due to:")
                    print("1. Private key format issues in the service account file")
                    print("2. System time not synchronized correctly")
                    print("3. Expired or revoked service account credentials")
                    print("Try re-downloading a new service account key from Firebase Console")
                else:
                    print(f"Error initializing Firebase: {str(e)}")
                db = None
except Exception as e:
    print(f"Unexpected error during Firebase initialization: {str(e)}")
    db = None

# Setup rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000 per day", "500 per hour"],
    storage_uri="memory://"
)

# In a production environment, use a proper database
USERS = {
    "admin": {
        "password": generate_password_hash("admin123"),
        "role": "admin"
    },
    "user": {
        "password": generate_password_hash("user123"),
        "role": "user"
    }
}

import os
import json

# Load videos from JSON file
def load_videos():
    """Load videos from all batch JSON files"""
    videos = []
    
    try:
        # Get all JSON files in the batches directory
        batch_files = [f for f in os.listdir('data/batches') if f.endswith('.json')]
        
        for batch_file in batch_files:
            try:
                with open(os.path.join('data/batches', batch_file), 'r', encoding='utf-8', errors='ignore') as f:
                    data = json.load(f)
                    batch_id = os.path.splitext(batch_file)[0]
            
                    # Extract videos from the batch data format
                    for subject_name, subject_data in data.get('subjects', {}).items():
                        for content in subject_data.get('content', []):
                            if content.get('type') == 'video' and 'video_data' in content:
                                video = {
                                    "id": content.get('video_data', {}).get('id', ''),
                                    "hash": content.get('video_data', {}).get('hash', ''),
                                    "key": content.get('video_data', {}).get('key', ''),
                                    "title": content.get('title', ''),
                                    "description": f"{subject_name}: {content.get('description', '')}",
                                    "thumbnail": content.get('thumbnail', ''),
                                    "duration": content.get('duration', "45:00"),  # Default duration if not provided
                                    "available_qualities": ["360p", "480p", "720p"],
                                    "subject": subject_name,
                                    "chapter": content.get('chapter', {}).get('name', ''),
                                    "batch_id": batch_id
                                }
                                
                                # Only add if it has a valid ID and not already in the list
                                if video["id"] and not any(v.get('id') == video["id"] for v in videos):
                                    videos.append(video)
            except Exception as e:
                print(f"Error loading batch file {batch_file}: {e}")
                continue
    except Exception as e:
        print(f"Error loading videos from batch files: {e}")
    
    # If we couldn't load any videos, try the fallback videos.json file
    if not videos:
        try:
            with open('videos.json', 'r') as f:
                data = json.load(f)
                videos = data.get('videos', [])
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading fallback videos.json: {e}")
    
    print(f"Loaded {len(videos)} videos from all batch files")
    print(f"Video IDs: {[v.get('id') for v in videos]}")
    return videos
# Video catalog - loaded from JSON file
VIDEOS = load_videos()

# Track active streaming sessions
ACTIVE_STREAMS = {}

# Track user sessions with additional security
USER_SESSIONS = {}

HEADER_DECRYPTION_BYTES = 28

# Session cookie lifetime (30 days in seconds)
SESSION_LIFETIME = 30 * 24 * 60 * 60

# Secret key for URL signing
URL_SECRET = os.environ.get('URL_SECRET', app.secret_key)

# Directory for cached profile images
PROFILE_IMAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'profile_images')
os.makedirs(PROFILE_IMAGES_DIR, exist_ok=True)

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        
        # Admin users bypass session integrity check
        if session.get('is_admin'):
            return f(*args, **kwargs)
        
        # Verify session integrity for regular users - more lenient check
        if 'session_id' not in session:
            session.clear()
            flash('Your session has expired. Please log in again.', 'error')
            return redirect(url_for('login'))
            
        # Even if session_id not in USER_SESSIONS, allow access but recreate it
        if session['session_id'] not in USER_SESSIONS:
            # Recreate the session entry
            USER_SESSIONS[session['session_id']] = {
                'user_id': session['user_id'],
                'uid': session.get('uid'),
                'ip': request.remote_addr,
                'user_agent': request.user_agent.string,
                'created_at': time.time(),
                'last_accessed': time.time(),
                'expires_at': time.time() + (365 * 24 * 60 * 60),
                'remember_me': True,
                'photo_url': session.get('photo_url'),
                'display_name': session.get('display_name')
            }
            
        # Update last accessed time
        if session['session_id'] in USER_SESSIONS:
            USER_SESSIONS[session['session_id']]['last_accessed'] = time.time()
            
        return f(*args, **kwargs)
    return decorated_function

def decrypt_byte(byte_value, index, key):
    """Decrypt a single byte using the given key and index."""
    if index < len(key):
        return byte_value ^ ord(key[index])
    else:
        return byte_value ^ index

def get_video_info(video_url):
    """
    Use yt_dlp to extract the direct video URL and file size.
    video_url is a fully constructed URL (without any query parameters).
    """
    ydl_opts = {
        'format': 'best',
        'skip_download': True,
        # Suppress verbose logging to keep output clean.
        'quiet': True,
    }
    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
        info_dict = ydl.extract_info(video_url, download=False)
    direct_url = info_dict.get('url')
    filesize = info_dict.get('filesize') or info_dict.get('filesize_approx')
    if direct_url and not filesize:
        head_resp = requests.head(direct_url)
        if head_resp.status_code == 200 and "Content-Length" in head_resp.headers:
            filesize = int(head_resp.headers["Content-Length"])
    return direct_url, filesize

def parse_range_header(range_header, filesize):
    """
    Parse the Range header into start and end positions.
    Returns (start, end) or None if header is malformed.
    """
    match = re.search(r"bytes=(\d+)-(\d*)", range_header)
    if match:
        start = int(match.group(1))
        end = match.group(2)
        if end:
            end = int(end)
        else:
            end = filesize - 1 if filesize else None
        return start, end
    return None

def generate_decrypted_stream(direct_url, range_start=0, range_end=None, custom_key=""):
    """
    Opens a streaming HTTP request to the direct URL with an optional Range header.
    Decrypts any portion of the first 28 bytes if the requested range overlaps that segment.
    Yields the resulting chunks.
    """
    headers = {}
    if range_start is not None:
        if range_end is not None:
            headers['Range'] = f"bytes={range_start}-{range_end}"
        else:
            headers['Range'] = f"bytes={range_start}-"

    response = requests.get(direct_url, stream=True, headers=headers)
    if response.status_code not in (200, 206):
        abort(response.status_code)

    bytes_processed = range_start
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        if bytes_processed < HEADER_DECRYPTION_BYTES:
            decrypt_up_to = min(HEADER_DECRYPTION_BYTES - bytes_processed, len(chunk))
            decrypted_part = bytearray(
                decrypt_byte(b, bytes_processed + i, custom_key)
                for i, b in enumerate(chunk[:decrypt_up_to])
            )
            yield bytes(decrypted_part) + chunk[decrypt_up_to:]
        else:
            yield chunk
        bytes_processed += len(chunk)

def generate_secure_token():
    """Generate a secure random token"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def generate_obfuscated_url(video_index, user_id):
    """Generate an obfuscated URL for a video"""
    # Create a timestamp to prevent replay attacks
    timestamp = int(time.time())
    
    # Create a random token
    token = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    
    # Create a payload with video index, timestamp, and token
    payload = f"{video_index}:{timestamp}:{token}"
    
    # Base64 encode the payload
    encoded_payload = base64.urlsafe_b64encode(payload.encode()).decode()
    
    # Create a signature using HMAC
    signature = hmac.new(
        URL_SECRET.encode(),
        encoded_payload.encode(),
        hashlib.sha256
    ).hexdigest()[:16]  # Use first 16 chars of signature
    
    # Combine everything into a complex-looking URL parameter
    auth_param = f"auth-site=MrGadhvii-JWTToken{token}-{encoded_payload}.{signature}"
    
    return auth_param

def decode_obfuscated_url(auth_param):
    """Decode an obfuscated URL parameter"""
    try:
        # Extract the encoded payload and signature
        parts = auth_param.split('auth-site=MrGadhvii-JWTToken')[1]
        token_parts = parts.split('-', 1)
        if len(token_parts) != 2:
            return None
            
        payload_sig = token_parts[1]
        payload_parts = payload_sig.split('.')
        if len(payload_parts) != 2:
            return None
            
        encoded_payload = payload_parts[0]
        signature = payload_parts[1]
        
        # Verify the signature
        expected_signature = hmac.new(
            URL_SECRET.encode(),
            encoded_payload.encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        
        if not hmac.compare_digest(signature, expected_signature):
            return None
        
        # Decode the payload
        payload = base64.urlsafe_b64decode(encoded_payload.encode()).decode()
        parts = payload.split(':')
        if len(parts) != 3:
            return None
            
        video_index = int(parts[0])
        timestamp = int(parts[1])
        
        # Check if the URL has expired (24 hour validity)
        if time.time() - timestamp > 86400:
            return None
            
        return video_index
    except Exception:
        return None

def generate_default_profile_image(user_id, display_name=None):
    """Generate a default profile image with the user's initial"""
    # Get the initial from display_name or user_id
    initial = ""
    if display_name and display_name.strip():
        initial = display_name[0].upper()
    elif user_id and user_id.strip():
        initial = user_id[0].upper()
    else:
        initial = "U"  # Default initial
    
    # Create a filename based on the user_id
    filename = f"{hashlib.md5(user_id.encode()).hexdigest()}_default.jpg"
    filepath = os.path.join(PROFILE_IMAGES_DIR, filename)
    
    # Check if we already have this image cached
    if os.path.exists(filepath):
        return f"/static/profile_images/{filename}"
    
    try:
        # Create a new image with a colored background
        img_size = 96
        img = Image.new('RGB', (img_size, img_size), color=(67, 97, 238))  # Primary color
        
        # Add text
        draw = ImageDraw.Draw(img)
        
        # Try to use a system font, fall back to default
        try:
            font_size = 48
            try:
                font = ImageFont.truetype("arial.ttf", font_size)
            except:
                font = ImageFont.load_default()
                
            # Calculate text position to center it
            try:
                # For newer Pillow versions
                text_width = draw.textlength(initial, font=font)
                font_metrics = font.getmetrics()
                text_height = font_metrics[0] + font_metrics[1]
            except AttributeError:
                # For older Pillow versions
                text_width, text_height = draw.textsize(initial, font=font)
                
            position = ((img_size - text_width) // 2, (img_size - text_height) // 2 - 5)
            
            # Draw the text
            draw.text(position, initial, fill=(255, 255, 255), font=font)
        except Exception as e:
            print(f"Error adding text to image: {e}")
            # Fallback to a simpler method
            draw.text((img_size // 3, img_size // 3), initial, fill=(255, 255, 255))
        
        # Save the image
        img.save(filepath, quality=90)
        return f"/static/profile_images/{filename}"
    except Exception as e:
        print(f"Error generating default profile image: {e}")
        return None

def download_and_cache_profile_image(photo_url, user_id, display_name=None):
    """Download and cache a user's profile image locally"""
    if not photo_url:
        return generate_default_profile_image(user_id, display_name)
        
    # Create a filename based on the user_id
    filename = f"{hashlib.md5(user_id.encode()).hexdigest()}.jpg"
    filepath = os.path.join(PROFILE_IMAGES_DIR, filename)
    
    # Check if we already have this image cached
    if os.path.exists(filepath):
        return f"/static/profile_images/{filename}"
    
    try:
        # Download the image
        response = requests.get(photo_url, timeout=5)
        if response.status_code != 200:
            return generate_default_profile_image(user_id, display_name)
            
        # Save the image
        with open(filepath, 'wb') as f:
            f.write(response.content)
            
        # Create a smaller version if needed
        try:
            img = Image.open(filepath)
            img = img.resize((96, 96))
            img.save(filepath, quality=85)
        except Exception as e:
            print(f"Error resizing image: {e}")
            
        return f"/static/profile_images/{filename}"
    except Exception as e:
        print(f"Error downloading profile image: {e}")
        return generate_default_profile_image(user_id, display_name)

@app.route('/')
def index():
    """Serve the index page with our custom player UI."""
    if 'user_id' in session:
        return render_template("index.html", videos=VIDEOS)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET'])
def login():
    """Handle user login"""
    return render_template('login.html')

@app.route('/firebase-login', methods=['POST'])
@limiter.limit("10 per minute")
def firebase_login():
    """Handle Firebase authentication"""
    try:
        # Get the token from the request
        token_data = request.json
        
        if not token_data or not token_data.get('uid'):
            return jsonify({"success": False, "error": "Invalid token data"}), 400
        
        # In production, you should verify the Firebase ID token
        # For simplicity, we're trusting the client-side token here
        # In a real app, use firebase_admin.auth.verify_id_token()
        
        # Create a unique session ID
        session_id = generate_secure_token()
        
        # Get user info
        photo_url = token_data.get('photoURL')
        user_id = token_data.get('email')
        display_name = token_data.get('displayName')
        
        # Download and cache the profile image
        cached_photo_url = download_and_cache_profile_image(photo_url, user_id, display_name)
        
        # Store user info in session
        session['user_id'] = user_id
        session['display_name'] = display_name
        session['photo_url'] = cached_photo_url or photo_url
        session['uid'] = token_data.get('uid')
        session['role'] = 'user'  # Default role
        session['session_id'] = session_id
        
        # Always make session permanent for reliable persistence
        session.permanent = True
        
        # Calculate session lifetime (always use long lifetime)
        session_lifetime = 365 * 24 * 60 * 60  # 365 days
        
        # Track session with IP and user agent for security
        USER_SESSIONS[session_id] = {
            'user_id': user_id,
            'uid': token_data.get('uid'),
            'ip': request.remote_addr,
            'user_agent': request.user_agent.string,
            'created_at': time.time(),
            'last_accessed': time.time(),
            'expires_at': time.time() + session_lifetime,
            'remember_me': True,
            'photo_url': cached_photo_url or photo_url,
            'display_name': display_name
        }
        
        # Save session data to disk
        session.modified = True
        
        # Create response with success message
        response = jsonify({"success": True})
        
        # Set a cookie for the session with appropriate expiration
        response.set_cookie(
                'session_token', 
                session_id, 
            max_age=session_lifetime, 
                httponly=True, 
            secure=False,  # Allow non-HTTPS for development 
                samesite='Lax'
            )
        
        return response
        
    except Exception as e:
        print(f"Firebase login error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/logout')
def logout():
    """Handle user logout"""
    if 'session_id' in session:
        USER_SESSIONS.pop(session['session_id'], None)
    
    # Clear session
    session.clear()
    
    # Create response
    response = make_response(redirect(url_for('login')))
    
    # Clear the permanent cookie
    response.set_cookie('session_token', '', expires=0)
    
    flash('You have been logged out', 'info')
    return response

# Global after_request handler for clearing invalid cookies
@app.after_request
def clear_invalid_cookie(response):
    """Clear invalid session cookies"""
    # This will only modify the response if needed
    # The actual check for invalid cookies is done in cleanup_sessions
    return response

# Apply cookie changes based on request flags
@app.after_request
def apply_cookie_changes(response):
    """Apply cookie changes based on request flags"""
    if hasattr(g, 'clear_session_cookie') and g.clear_session_cookie:
        response.set_cookie('session_token', '', expires=0)
    return response

@app.before_request
def cleanup_sessions():
    """Remove expired sessions and handle auto-login"""
    current_time = time.time()
    
    # Remove expired sessions
    expired_sessions = [sid for sid, data in USER_SESSIONS.items() 
                        if data.get('expires_at') is not None and data.get('expires_at', 0) < current_time]
    
    for sid in expired_sessions:
        USER_SESSIONS.pop(sid, None)
    
    # Skip auto-login for login and static routes
    if request.endpoint in ['login', 'firebase_login', 'static']:
        return
        
    # Check if there's a session token cookie but no session
    if 'user_id' not in session and request.cookies.get('session_token'):
        token = request.cookies.get('session_token')
        if token in USER_SESSIONS:
            # Restore session from cookie
            user_data = USER_SESSIONS[token]
            
            # Verify IP and user agent for security (optional, can be disabled)
            # if user_data.get('ip') != request.remote_addr or user_data.get('user_agent') != request.user_agent.string:
            #     return redirect(url_for('login'))
            
            # Restore session data
            session['user_id'] = user_data.get('user_id')
            session['uid'] = user_data.get('uid')
            session['role'] = 'user'
            session['session_id'] = token
            session['photo_url'] = user_data.get('photo_url')
            session['display_name'] = user_data.get('display_name', user_data.get('user_id'))
            session.permanent = user_data.get('remember_me', True)
            
            # Update last accessed time
            USER_SESSIONS[token]['last_accessed'] = current_time
            
            # Save session data to disk
            session.modified = True
            
            # If this is an API request, continue
            # If it's a page request, redirect to the requested page
            if request.path.startswith('/api/'):
                return
        else:
            # Invalid token, mark for clearing in the after_request handler
            g.clear_session_cookie = True

@app.route('/api/videos')
@login_required
def get_videos():
    """API endpoint to get the list of videos"""
    return jsonify(VIDEOS)

@app.route('/authorize-stream', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def authorize_stream():
    """Generate a temporary token for video streaming"""
    video_id = request.form.get('video_id')
    video_hash = request.form.get('hash')
    video_key = request.form.get('key')
    quality = request.form.get('quality', '360p')
    
    if not (video_id and video_hash and video_key):
        return jsonify({"error": "Missing parameters"}), 400
    
    # Generate a unique token for this streaming session
    stream_token = str(uuid.uuid4())
    
    # Store the token with video details (with expiration)
    expiry = int(time.time()) + 3600  # 1 hour validity
    ACTIVE_STREAMS[stream_token] = {
        "video_id": video_id,
        "hash": video_hash,
        "key": video_key,
        "quality": quality,
        "user": session['user_id'],
        "session_id": session['session_id'],
        "ip": request.remote_addr,
        "user_agent": request.user_agent.string,
        "expires": expiry
    }
    
    return jsonify({
        "token": stream_token,
        "expires": expiry
    })

@app.route('/stream')
@login_required
@limiter.limit("500 per hour")
def stream_video():
    """
    Stream endpoint.
    Expects a valid stream token that was previously authorized.
    """
    stream_token = request.args.get("token")
    
    # Validate the token
    if not stream_token or stream_token not in ACTIVE_STREAMS:
        return "Invalid or expired stream token", 403
    
    stream_data = ACTIVE_STREAMS[stream_token]
    
    # Check if token has expired
    if stream_data["expires"] < int(time.time()):
        ACTIVE_STREAMS.pop(stream_token, None)
        return "Stream token expired", 403
    
    # Enhanced security checks
    # 1. Check if the user is the same who requested the token
    if stream_data["user"] != session['user_id']:
        return "Unauthorized access", 403
        
    # 2. Check if the session is the same
    if stream_data["session_id"] != session.get('session_id'):
        return "Session mismatch", 403
        
    # 3. Check if IP address matches (optional, can cause issues with dynamic IPs)
    if stream_data["ip"] != request.remote_addr:
        return "IP address mismatch", 403
        
    # 4. Check if user agent matches (helps prevent token theft)
    if stream_data["user_agent"] != request.user_agent.string:
        return "User agent mismatch", 403
    
    video_id = stream_data["video_id"]
    video_hash = stream_data["hash"]
    custom_key = stream_data["key"]
    quality = stream_data["quality"]
    
    # Ensure the hash starts with a dash.
    if not video_hash.startswith('-'):
        video_hash = '-' + video_hash

    base_url = f"https://appx-transcoded-videos.livelearn.in/videos/firephysics-data/{video_id}/encrypted{video_hash}/{quality}/encrypted.mkv"
    
    try:
        direct_url, filesize = get_video_info(base_url)
    except Exception as e:
        # If extraction fails (e.g. 404 for the chosen quality) and quality is not default,
        # fall back to default quality "360p"
        if quality != "360p":
            fallback_url = f"https://appx-transcoded-videos.livelearn.in/videos/firephysics-data/{video_hash}/360p/encrypted.mkv"
            try:
                direct_url, filesize = get_video_info(fallback_url)
            except Exception as e:
                return "Error retrieving video.", 500
        else:
            return "Error retrieving video.", 500

    if not direct_url:
        return "Unable to retrieve video.", 500

    # Create response with anti-download headers
    range_header = request.headers.get('Range', None)
    if range_header and filesize:
        parsed_range = parse_range_header(range_header, filesize)
        if parsed_range is None:
            return Response(status=416)
        range_start, range_end = parsed_range
        if range_start >= filesize or (range_end is not None and range_end >= filesize):
            return Response(
                status=416,
                headers={"Content-Range": f"bytes */{filesize}"}
            )
        content_length = (range_end - range_start + 1) if range_end is not None else filesize - range_start
        headers = {
            "Content-Range": f"bytes {range_start}-{range_start + content_length - 1}/{filesize}",
            "Accept-Ranges": "bytes",
            "Content-Length": str(content_length),
            "Content-Disposition": "inline",  # Force browser to play inline
            "X-Content-Type-Options": "nosniff",  # Prevent MIME type sniffing
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",  # Prevent caching
            "Pragma": "no-cache"
        }
        response = Response(
            stream_with_context(generate_decrypted_stream(direct_url, range_start, range_end, custom_key)),
            status=206,
            headers=headers,
            mimetype='video/mp4'
        )
    else:
        headers = {
            "Content-Disposition": "inline",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache"
        }
        response = Response(
            stream_with_context(generate_decrypted_stream(direct_url, custom_key=custom_key)),
            headers=headers,
            mimetype='video/mp4'
        )
    
    # Add cookie to track the stream token (helps with security)
    response.set_cookie(
        'stream_token', 
        stream_token, 
        httponly=True, 
        secure=request.is_secure, 
        samesite='Strict',
        max_age=3600
    )
    
    return response

@app.route('/player/<path:auth_param>')
@login_required
def player_obfuscated(auth_param):
    """Player page that accepts an obfuscated URL parameter"""
    try:
        # Decode the parameter
        video_index_str = decode_obfuscated_url(auth_param)
        if not video_index_str:
            flash("Invalid video URL", "error")
            return redirect(url_for('index'))
        
        # Get video index
        video_index = int(video_index_str)
        
        # Ensure the video index is valid
        if video_index < 0 or video_index >= len(VIDEOS):
            flash("Video not found", "error")
            return redirect(url_for('index'))
        
        # Get video data
        video_data = VIDEOS[video_index]
        
        # Generate a secure token for streaming
        token = generate_secure_token()
        
        # Store token with video info (expires in 2 hours)
        ACTIVE_STREAMS[token] = {
            "user_id": session.get("user_id", ""),
            "video_id": video_data.get("id", ""),
            "hash": video_data.get("hash", ""),
            "key": video_data.get("key", ""),
            "quality": DEFAULT_QUALITY,
            "expires": int(time.time()) + 7200  # 2 hours
        }
        
        # Update video_data to include token and other player info
        player_data = video_data.copy()
        player_data["token"] = token
        player_data["stream_url"] = f"/stream?token={token}"
        
        return render_template('player.html', video=player_data)
    
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
        return redirect(url_for('index'))

@app.route('/player/<int:video_index>')
@login_required
def player(video_index):
    """Player page that accepts a video index parameter"""
    # Get video data
    if video_index < 0 or video_index >= len(VIDEOS):
        flash("Video not found", "error")
        return redirect(url_for('index'))
        
    video_data = VIDEOS[video_index]
    
    # Generate a secure token for streaming
    token = generate_secure_token()
    
    # Store token with video info (expires in 2 hours)
    ACTIVE_STREAMS[token] = {
        "user_id": session.get("user_id", ""),
        "video_id": video_data.get("id", ""),
        "hash": video_data.get("hash", ""),
        "key": video_data.get("key", ""),
        "quality": DEFAULT_QUALITY,
        "expires": int(time.time()) + 7200  # 2 hours
    }
    
    # Update video_data to include token and other player info
    player_data = video_data.copy()
    player_data["token"] = token
    player_data["stream_url"] = f"/stream?token={token}"
    
    return render_template('player.html', video=player_data)

@app.route('/player/video/<path:video_id>')
@login_required
def player_by_id(video_id):
    """Serve the video player page with direct video ID, hash, and key"""
    video_hash = request.args.get('hash')
    video_key = request.args.get('key')
    video_url = request.args.get('url')
    
    # Find the video in the videos list
    video = None
    for v in VIDEOS:
        if v['id'] == video_id:
            video = v
            break
    
    if not video:
        flash('Video not found', 'error')
        return redirect(url_for('index'))
    
    # Check if downloads are enabled from admin settings
    # Default to False if not specified
    enable_download = False
    if db:
        try:
            settings_ref = db.collection('settings').document('video_player')
            settings = settings_ref.get()
            if settings.exists:
                settings_data = settings.to_dict()
                enable_download = settings_data.get('enable_download', False)
        except Exception as e:
            print(f"Error fetching download settings: {e}")
    
    # Create a video object with the provided parameters
    video_data = {
        "id": video_id,
        "hash": video_hash,
        "key": video_key,
        "url": video_url,
        "title": video.get('title', 'Video'),
        "description": video.get('description', ''),
        "thumbnail": video.get('thumbnail', ''),
        "duration": video.get('duration', ''),
        "available_qualities": video.get('available_qualities', ['360p']),
        "subject": video.get('subject', ''),
        "chapter": video.get('chapter', ''),
        "is_zip": video_url and '.zip' in video_url.lower(),
        "enable_download": enable_download
    }
    
    # If it's a zip video, use the zip player template
    if video_data['is_zip']:
        return render_template('zipplayer.html', video=video_data)
    
    # Otherwise, use the regular player template
    return render_template('player.html', video=video_data)

@app.route('/player/v2/<path:video_id>')
@login_required
def player_v2(video_id):
    """Serve the video player page for zip-based videos"""
    video_url = request.args.get('url')
    
    if not video_url or '.zip' not in video_url.lower():
        flash('Invalid video URL', 'error')
        return redirect(url_for('index'))
    
    # Find the video in the videos list
    video = None
    for v in VIDEOS:
        if v['id'] == video_id:
            video = v
            break
    
    if not video:
        flash('Video not found', 'error')
        return redirect(url_for('index'))
    
    # Create a video object with the provided parameters
    video_data = {
        "id": video_id,
        "url": video_url,
        "title": video.get('title', 'Video'),
        "description": video.get('description', ''),
        "thumbnail": video.get('thumbnail', ''),
        "duration": video.get('duration', ''),
        "subject": video.get('subject', ''),
        "chapter": video.get('chapter', '')
    }
    
    return render_template('zipplayer.html', video=video_data)

@app.route('/testurl')
def test_url():
    """Test direct URL playback"""
    url = request.args.get('url')
    if not url:
        return render_template('test_url_form.html')
    
    # Check if this is a zip-based HLS video
    is_zip_video = '.zip' in url.lower()
    
    try:
        if is_zip_video:
            # For zip-based videos, extract video ID from the URL
            # Format: https://transcoded-videos-v2.classx.co.in/videos/firephysics-data/VIDEO_ID/encrypted-HASH/QUALITY.zip
            parts = url.split('/')
            if len(parts) < 7:
                return "Invalid ZIP video URL format", 400
                
            video_id = parts[-3].split('-')[0] if '-' in parts[-3] else parts[-3]
            
            # Create a test video object for zip video
            test_video = {
                "id": video_id,
                "url": url,
                "title": "Shared HLS Video",
                "description": "Shared via VidH",
                "thumbnail": "https://via.placeholder.com/640x360.png?text=Shared+HLS+Video",
                "duration": "Unknown",
                "is_zip": True
            }
            
            # Get the m3u8 content by making a request to our hls-stream endpoint
            # This will also set up the session data for playback
            stream_response = hls_stream()
            if hasattr(stream_response, 'data'):
                # If we got a valid response, store the m3u8 content in the session
                session_id = str(hash(url))
                if 'hls_sessions' in session and session_id in session['hls_sessions']:
                    test_video['m3u8_content'] = session['hls_sessions'][session_id].get('m3u8_content', '')
            
            return render_template('zipplayer.html', video=test_video)
            
        else:
            # For regular videos, extract video details from the URL
            # Format: https://appx-transcoded-videos.livelearn.in/videos/firephysics-data/VIDEO_ID/encrypted-HASH/QUALITY/encrypted.mkv*KEY
            parts = url.split('/')
        if len(parts) < 7:
            return "Invalid URL format", 400
            
        video_id = parts[-4].split('-')[0] if '-' in parts[-4] else parts[-4]
        hash_part = parts[-3].split('-')[1] if '-' in parts[-3] else parts[-3]
        quality = parts[-2]
        
        # Extract key from the last part if it contains *
        if '*' in parts[-1]:
            key = parts[-1].split('*')[1]
        else:
            key = ""
        
        # Create a test video object
        test_video = {
            "id": video_id,
            "hash": hash_part,
            "key": key,
            "title": "Shared Video",
            "description": "Shared via VidH",
            "thumbnail": "https://via.placeholder.com/640x360.png?text=Shared+Video",
            "duration": "Unknown",
            "available_qualities": [quality],
                "direct_url": url,
                "is_zip": False
        }
        
        # Generate a random token for the URL
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        timestamp = int(time.time())
        
        # Add obfuscated URL info to the template context
        test_video['auth_token'] = token
        test_video['timestamp'] = timestamp
        test_video['auth_signature'] = hmac.new(
            URL_SECRET.encode(),
            f"{video_id}:{timestamp}:{token}".encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        
        return render_template('test_player.html', video=test_video)
            
    except Exception as e:
        return f"Error parsing URL: {str(e)}", 400

@app.route('/secure-test/<path:auth_param>')
@login_required
def secure_test(auth_param):
    """Secure test URL endpoint with obfuscated URL"""
    try:
        # Extract the token and URL from the auth param
        if not auth_param.startswith('auth-site=MrGadhvii-JWTToken'):
            return "Invalid URL format", 400
            
        # Extract the URL from the auth param
        url_param = request.args.get('url')
        if not url_param:
            return "Missing URL parameter", 400
            
        # Decode the URL parameter
        url = base64.urlsafe_b64decode(url_param.encode()).decode()
        
        return redirect(url_for('test_url', url=url))
    except Exception as e:
        return f"Error processing URL: {str(e)}", 400

@app.route('/direct-stream')
@limiter.limit("500 per hour")
def direct_stream():
    """Stream a video directly from the provided URL with decryption"""
    url = request.args.get('url')
    key = request.args.get('key', '')
    download = request.args.get('download', 'false').lower() == 'true'
    
    if not url:
        return "Missing URL parameter", 400
    
    # If URL contains a key (format: url*key), extract it
    if '*' in url:
        parts = url.split('*')
        url = parts[0]
        if len(parts) > 1 and not key:
            key = parts[1]
    
    # Force 360p quality temporarily
    if '/encrypted-' in url:
        # Extract parts before and after quality
        url_parts = url.split('/encrypted-')
        if len(url_parts) == 2:
            base_part = url_parts[0]
            after_part = url_parts[1]
            
            # Split after part by / to get hash and the rest
            after_parts = after_part.split('/', 1)
            if len(after_parts) == 2:
                hash_part = after_parts[0]
                rest_part = after_parts[1]
                
                # Replace quality with 360p
                rest_parts = rest_part.split('/', 1)
                if len(rest_parts) == 2:
                    url = f"{base_part}/encrypted-{hash_part}/360p/{rest_parts[1]}"
    
    try:
        # Get video info without yt-dlp for direct URLs
        if url.startswith('https://appx-transcoded-videos.livelearn.in'):
            # For direct URLs, we can make a HEAD request to get the file size
            head_resp = requests.head(url)
            if head_resp.status_code != 200:
                return f"Error accessing video: HTTP {head_resp.status_code}", 500
                
            filesize = int(head_resp.headers.get("Content-Length", 0))
            direct_url = url
        else:
            # Use yt-dlp for other URLs
            direct_url, filesize = get_video_info(url)
    
        if not direct_url:
            return "Unable to retrieve video URL", 500
            
        # Extract filename from URL or use a default one
        url_path = direct_url.split('/')[-1]
        filename = url_path.split('*')[0] if '*' in url_path else url_path
        if not filename or filename == 'encrypted.mkv':
            filename = f"video_{int(time.time())}.mp4"
    
        # Create response with appropriate headers based on download flag
        range_header = request.headers.get('Range', None)
        if range_header and filesize:
            parsed_range = parse_range_header(range_header, filesize)
            if parsed_range is None:
                return Response(status=416)
            range_start, range_end = parsed_range
            if range_start >= filesize or (range_end is not None and range_end >= filesize):
                return Response(
                    status=416,
                    headers={"Content-Range": f"bytes */{filesize}"}
                )
            content_length = (range_end - range_start + 1) if range_end is not None else filesize - range_start
            headers = {
                "Content-Range": f"bytes {range_start}-{range_start + content_length - 1}/{filesize}",
                "Accept-Ranges": "bytes",
                "Content-Length": str(content_length),
                "Content-Disposition": f"attachment; filename=\"{filename}\"" if download else "inline", # Changed to attachment if download is true
                "X-Content-Type-Options": "nosniff",  # Prevent MIME type sniffing
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",  # Prevent caching
                "Pragma": "no-cache"
            }
            response = Response(
                stream_with_context(generate_decrypted_stream(direct_url, range_start, range_end, key)),
                status=206,
                headers=headers,
                mimetype='video/mp4'
            )
        else:
            headers = {
                "Content-Disposition": f"attachment; filename=\"{filename}\"" if download else "inline", # Changed to attachment if download is true
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache"
            }
            response = Response(
                stream_with_context(generate_decrypted_stream(direct_url, custom_key=key)),
                headers=headers,
                mimetype='video/mp4'
            )
        
        return response
    except Exception as e:
        print(f"Streaming error: {str(e)}")
        return f"Error streaming video: {str(e)}", 500

@app.route('/profile-image/<user_id>')
def profile_image(user_id):
    """Generate or serve a profile image for a user"""
    # Check if a custom profile image exists
    profile_dir = os.path.join('static', 'profile_images')
    os.makedirs(profile_dir, exist_ok=True)
    
    # Check for existing image files with various extensions
    for ext in ['jpg', 'jpeg', 'png', 'gif']:
        img_path = os.path.join(profile_dir, f"{user_id}.{ext}")
        if os.path.exists(img_path):
            return send_file(img_path, mimetype=f'image/{ext}')
    
    # Generate a default avatar if no image exists
    # Create a colored background with the first letter of the username
    size = 200
    img = Image.new('RGB', (size, size), color=(67, 97, 238))
    draw = ImageDraw.Draw(img)
    
    # Try to get a font, use default if not available
    try:
        font_size = 100
        font = ImageFont.truetype("arial.ttf", font_size)
    except IOError:
        font = ImageFont.load_default()
    
    # Get the first letter of the user_id or use a default
    letter = user_id[0].upper() if user_id else "U"
    
    # Calculate text position to center it
    text_width, text_height = draw.textsize(letter, font=font) if hasattr(draw, 'textsize') else (font_size, font_size)
    position = ((size - text_width) // 2, (size - text_height) // 2 - 10)
    
    # Draw the letter
    draw.text(position, letter, fill=(255, 255, 255), font=font)
    
    # Save the image to a bytes buffer
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    
    # Cache the image for future use
    img_path = os.path.join(profile_dir, f"{user_id}.png")
    img.save(img_path, 'PNG')
    
    return send_file(img_io, mimetype='image/png')

def get_current_user():
    """Get the current user from the session"""
    if 'user_id' not in session:
        return None
        
    return {
        'id': session['user_id'],
        'name': session.get('display_name', session['user_id']),
        'photo_url': session.get('photo_url')
    }

@app.route('/generate-share-link', methods=['POST'])
@login_required
def generate_share_link():
    try:
        # Get data from request
        data = request.get_json()
        
        # Validate required fields
        if not data or 'video_id' not in data:
            return jsonify({'error': 'Missing required video_id parameter'}), 400
            
        video_id = data.get('video_id')
        batch_id = data.get('batch_id')
        subject = data.get('subject')
        expiry_days = data.get('expiry_days', 7)  # Default to 7 days if not specified
        
        # Get current user
        current_user = get_current_user()
        if not current_user:
            return jsonify({'error': 'User not authenticated'}), 401
            
        # Generate a unique token for the share
        share_token = secrets.token_urlsafe(16)
        
        # Set expiry date
        expiry_date = datetime.now() + timedelta(days=expiry_days)
        
        # Create shared video entry
        shared_video = {
            'id': share_token,
            'video_id': video_id,
            'batch_id': batch_id,
            'subject': subject,
            'shared_by': current_user.get('name', 'Unknown'),
            'shared_at': datetime.now().isoformat(),
            'expires_at': expiry_date.isoformat(),
            'views': 0,
            'is_active': True,
            'created_at': datetime.now().isoformat()
        }
        
        # Save to shared videos collection
        if not db:
            return jsonify({'error': 'Database not available'}), 500
            
        db.collection('share_links_v2').document(share_token).set(shared_video)
        
        # Generate the share URL using the correct route name
        share_url = url_for('access_shared_link', share_id=share_token, _external=True)
        
        return jsonify({
            'success': True,
            'share_url': share_url,
            'expires_at': expiry_date.isoformat()
        })
        
    except Exception as e:
        print(f"Error generating share link: {str(e)}")
        return jsonify({'error': f'Failed to generate share link: {str(e)}'}), 500

@app.route('/shared/<share_id>')
def access_shared_link(share_id):
    """Access a shared video link - no login required"""
    try:
        if not db:
            print("Database not available")
            return "Database not available", 500
            
        print(f"Accessing share link: {share_id}")
            
        # Get share link data from Firestore
        share_doc = db.collection('share_links_v2').document(share_id).get()
        
        if not share_doc.exists:
            print(f"Share link not found: {share_id}")
            flash("This share link doesn't exist or has expired", "error")
            # Redirect to login page instead of index for non-logged in users
            return render_template('shared_not_found.html', error="This share link doesn't exist or has expired")
            
        share_data = share_doc.to_dict()
        print(f"Share data: {share_data}")
        
        # Check if link is active and not expired
        if not share_data.get('is_active'):
            print(f"Share link is not active: {share_id}")
            flash("This share link has been disabled", "error")
            return render_template('shared_not_found.html', error="This share link has been disabled")
            
        expires_at = datetime.fromisoformat(share_data.get('expires_at'))
        if expires_at < datetime.now():
            print(f"Share link has expired: {share_id}")
            flash("This share link has expired", "error")
            return render_template('shared_not_found.html', error="This share link has expired")
            
        # Get video details
        video_id = share_data.get('video_id')
        if not video_id:
            print(f"Missing video ID in share data: {share_data}")
            flash("Invalid share link: missing video ID", "error")
            return render_template('shared_not_found.html', error="Invalid share link: missing video ID")
            
        print(f"Looking for video with ID: {video_id}")
        print(f"Available videos: {[v.get('id') for v in VIDEOS]}")
        
        # First try to find the video in the VIDEOS list
        video = None
        for v in VIDEOS:
            if v.get('id') == video_id:
                video = v
                print(f"Found video in VIDEOS list: {video}")
                break
                
        # If not found in VIDEOS, try to find in batch data
        if not video:
            batch_id = share_data.get('batch_id')
            if batch_id:
                print(f"Looking for video in batch: {batch_id}")
                try:
                    batch_file = os.path.join('data/batches', f"{batch_id}.json")
                    print(f"Checking batch file at: {batch_file}")
                    
                    if os.path.exists(batch_file):
                        print(f"Batch file exists, loading data...")
                        with open(batch_file, 'r') as f:
                            batch_data = json.load(f)
                            print(f"Subjects in batch: {list(batch_data.get('subjects', {}).keys())}")
                            
                            # Loop through all subjects in the batch
                            for subject_name, subject_data in batch_data.get('subjects', {}).items():
                                print(f"Checking subject: {subject_name}")
                                
                                # Check each content item in the subject
                                for content in subject_data.get('content', []):
                                    content_video_id = content.get('video_data', {}).get('id')
                                    
                                    print(f"Checking content item with video ID: {content_video_id}")
                                    
                                    if content_video_id == video_id:
                                        print(f"Found matching video in batch!")
                                        video = {
                                            "id": video_id,
                                            "hash": content.get('video_data', {}).get('hash', ''),
                                            "key": content.get('video_data', {}).get('key', ''),
                                            "title": content.get('title', 'Video'),
                                            "description": content.get('description', ''),
                                            "thumbnail": content.get('thumbnail', ''),
                                            "duration": content.get('duration', 'Unknown'),
                                            "subject": subject_name,
                                            "chapter": content.get('chapter', {}).get('name', '')
                                        }
                                        print(f"Found video in batch data: {video}")
                                        break
                                
                                if video:
                                    break
                    else:
                        print(f"Batch file does not exist: {batch_file}")
                        # Check all batch files as a fallback
                        print("Looking in all batch files as fallback...")
                        batch_files = os.listdir('data/batches')
                        for bf in batch_files:
                            if bf.endswith('.json'):
                                bf_path = os.path.join('data/batches', bf)
                                print(f"Checking batch file: {bf_path}")
                                try:
                                    with open(bf_path, 'r') as f:
                                        batch_data = json.load(f)
                                        for subject_name, subject_data in batch_data.get('subjects', {}).items():
                                            for content in subject_data.get('content', []):
                                                content_video_id = content.get('video_data', {}).get('id')
                                                if content_video_id == video_id:
                                                    video = {
                                                        "id": video_id,
                                                        "hash": content.get('video_data', {}).get('hash', ''),
                                                        "key": content.get('video_data', {}).get('key', ''),
                                                        "title": content.get('title', 'Video'),
                                                        "description": content.get('description', ''),
                                                        "thumbnail": content.get('thumbnail', ''),
                                                        "duration": content.get('duration', 'Unknown'),
                                                        "subject": subject_name,
                                                        "chapter": content.get('chapter', {}).get('name', '')
                                                    }
                                                    print(f"Found video in fallback batch file {bf}: {video}")
                                                    break
                                            if video:
                                                break
                                        if video:
                                            break
                                except Exception as e:
                                    print(f"Error reading fallback batch file {bf}: {str(e)}")
                except Exception as e:
                    print(f"Error reading batch file: {str(e)}")
                    print(f"Exception details: {traceback.format_exc()}")
                
        # If still not found, check if there might be a newly loaded video
        if not video:
            # Try to reload videos
            print("Video not found in VIDEOS or batch files. Trying to reload videos...")
            try:
                load_videos()
                print(f"Reloaded videos. New count: {len(VIDEOS)}")
                print(f"Reloaded video IDs: {[v.get('id') for v in VIDEOS]}")
                
                # Check again in the reloaded videos
                for v in VIDEOS:
                    if v.get('id') == video_id:
                        video = v
                        print(f"Found video in reloaded VIDEOS list: {video}")
                        break
            except Exception as e:
                print(f"Error reloading videos: {str(e)}")
                
        if not video:
            print(f"Video not found with ID: {video_id}")
            print(f"Available videos: {[v.get('id') for v in VIDEOS]}")
            flash(f"Video not found. The video ID {video_id} is not available in the system.", "error")
            return render_template('shared_not_found.html', error=f"Video not found. The video ID {video_id} is not available in the system.")
        
        # Create a test video object with additional share info
        test_video = {
            "id": video['id'],
            "hash": video.get('hash', ''),
            "key": video.get('key', ''),
            "title": video.get('title', 'Shared Video'),
            "description": video.get('description', ''),
            "thumbnail": video.get('thumbnail') or "https://via.placeholder.com/640x360.png?text=Shared+Video",
            "duration": video.get('duration', 'Unknown'),
            "available_qualities": ["360p"],
            "direct_url": f"https://appx-transcoded-videos.livelearn.in/videos/firephysics-data/{video['id']}/encrypted-{video.get('hash', '')}/360p/encrypted.mkv*{video.get('key', '')}",
            "shared_by": share_data.get('shared_by', 'Unknown'),
            "expires_at": expires_at.strftime('%Y-%m-%d %H:%M:%S'),
            "share_id": share_id
        }
        
        # Generate a random token for the URL
        token = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        timestamp = int(time.time())
        
        # Add obfuscated URL info to the template context
        test_video['auth_token'] = token
        test_video['timestamp'] = timestamp
        test_video['auth_signature'] = hmac.new(
            URL_SECRET.encode(),
            f"{video_id}:{timestamp}:{token}".encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        
        print(f"Rendering shared video template with data: {test_video}")
        return render_template('shared_video.html', video=test_video)
    except Exception as e:
        print(f"Error accessing shared link: {str(e)}")
        print(f"Exception details: {traceback.format_exc()}")
        flash(f"Error accessing shared link: {str(e)}", "error")
        return render_template('shared_not_found.html', error=f"Error accessing shared link: {str(e)}")

@app.route('/sharelinks')
def share_links_admin():
    """Admin page to manage share links"""
    # First check if a password is provided in the URL
    password = request.args.get('pass')
    if password and password == ADMIN_PASSWORD:
        # Set admin session
        session['user_id'] = 'admin@vidh.com'
        session['display_name'] = 'Admin'
        session['is_admin'] = True
        session['session_id'] = generate_secure_token()
        session.permanent = True
        
        # Generate session token for cookie
        session_id = session['session_id']
        USER_SESSIONS[session_id] = {
            'user_id': session['user_id'],
            'ip': request.remote_addr,
            'user_agent': request.user_agent.string,
            'created_at': time.time(),
            'last_accessed': time.time(),
            'expires_at': time.time() + 365 * 24 * 60 * 60,  # 365 days
            'remember_me': True,
            'is_admin': True,
            'display_name': 'Admin'
        }
        
        session.modified = True
        
        # Redirect to the same page without the password parameter for security
        return redirect(url_for('share_links_admin'))

    # Then check if user is logged in via session
    if 'user_id' not in session:
        flash('Please log in to access this page', 'error')
        return redirect(url_for('login'))
        
    try:
        share_links = []
        
        # Check if Firebase is available
        if db:
            try:
                # Get all share links from Firestore
                share_docs = db.collection('share_links_v2').order_by('created_at', direction=firestore.Query.DESCENDING).stream()
        
                for doc in share_docs:
                    share_data = doc.to_dict()
                    # Add formatted dates for display
                    created_at = datetime.fromisoformat(share_data.get('created_at'))
                    expires_at = datetime.fromisoformat(share_data.get('expires_at'))
                    
                    share_data['created_at_formatted'] = created_at.strftime('%Y-%m-%d %H:%M:%S')
                    share_data['expires_at_formatted'] = expires_at.strftime('%Y-%m-%d %H:%M:%S')
                    share_data['is_expired'] = expires_at < datetime.now()
                    
                    share_links.append(share_data)
            except Exception as e:
                print(f"Error fetching from Firebase: {e}")
                # Continue to local file fallback
        
        # If Firebase is not available or no links were found, try local file
        if not db or not share_links:
            print("Using local share links file")
            # Create directory if it doesn't exist
            os.makedirs('data/shares', exist_ok=True)
            
            # Check if local file exists
            local_file = os.path.join('data', 'shares', 'share_links.json')
            if os.path.exists(local_file):
                try:
                    with open(local_file, 'r') as f:
                        share_links = json.load(f)
                        
                    # Format dates
                    for share_data in share_links:
                        if 'created_at' in share_data:
                            try:
                                created_at = datetime.fromisoformat(share_data.get('created_at'))
                                share_data['created_at_formatted'] = created_at.strftime('%Y-%m-%d %H:%M:%S')
                            except:
                                share_data['created_at_formatted'] = 'Unknown'
                                
                        if 'expires_at' in share_data:
                            try:
                                expires_at = datetime.fromisoformat(share_data.get('expires_at'))
                                share_data['expires_at_formatted'] = expires_at.strftime('%Y-%m-%d %H:%M:%S')
                                share_data['is_expired'] = expires_at < datetime.now()
                            except:
                                share_data['expires_at_formatted'] = 'Unknown'
                                share_data['is_expired'] = False
                except Exception as e:
                    print(f"Error reading local share links file: {e}")
            
            # If still no links, create sample data for demonstration
            if not share_links:
                print("Creating sample share links")
                share_links = [{
                    "id": "sample-link-1",
                    "video_id": "sample-video-1",
                    "shared_by": "Admin",
                    "shared_at": datetime.now().isoformat(),
                    "expires_at": (datetime.now() + timedelta(days=7)).isoformat(),
                    "views": 0,
                    "is_active": True,
                    "created_at": datetime.now().isoformat(),
                    "created_at_formatted": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "expires_at_formatted": (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S'),
                    "is_expired": False
                }]
                
                # Save sample data
                try:
                    with open(local_file, 'w') as f:
                        json.dump(share_links, f)
                except Exception as e:
                    print(f"Error saving sample share links: {e}")
        
        return render_template('share_links_admin.html', share_links=share_links, db_available=(db is not None))
    except Exception as e:
        flash(f"Error loading share links: {str(e)}", "error")
        return redirect(url_for('index'))


@app.route('/api/sharelinks/disable-all', methods=['POST'])
@login_required
def disable_all_share_links():
    """Disable all share links"""
    # Check if user is admin
    admin_password = request.json.get('password')
    if admin_password != ADMIN_PASSWORD:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    try:
        # If Firebase is available
        if db:
            try:
                # Get all share links
                share_docs = db.collection('share_links_v2').stream()
                batch = db.batch()
        
                # Disable all links
                for doc in share_docs:
                    doc_ref = db.collection('share_links_v2').document(doc.id)
                    batch.update(doc_ref, {'is_active': False})
            
                # Commit the batch
                batch.commit()
                return jsonify({'success': True, 'message': 'All share links have been disabled in Firebase'})
            except Exception as e:
                print(f"Error disabling links in Firebase: {e}")
                # Continue to local file fallback
        
        # Local file fallback
        local_file = os.path.join('data', 'shares', 'share_links.json')
        if os.path.exists(local_file):
            try:
                # Read current links
                with open(local_file, 'r') as f:
                    share_links = json.load(f)
                
                # Disable all links
                for link in share_links:
                    link['is_active'] = False
                
                # Save updated links
                with open(local_file, 'w') as f:
                    json.dump(share_links, f)
                
                return jsonify({'success': True, 'message': 'All share links have been disabled in local storage'})
            except Exception as e:
                return jsonify({'success': False, 'message': f"Error updating local file: {str(e)}"}), 500
        else:
            return jsonify({'success': False, 'message': 'No share links available to disable'}), 404
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/sharelinks/delete-all', methods=['POST'])
@login_required
def delete_all_share_links():
    """Delete all share links"""
    # Check if user is admin
    admin_password = request.json.get('password')
    if admin_password != ADMIN_PASSWORD:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    try:
        # If Firebase is available
        if db:
            try:
                # Get all share links
                share_docs = db.collection('share_links_v2').stream()
                batch = db.batch()
        
                # Delete all links
                for doc in share_docs:
                    doc_ref = db.collection('share_links_v2').document(doc.id)
                    batch.delete(doc_ref)
                
                # Commit the batch
                batch.commit()
                return jsonify({'success': True, 'message': 'All share links have been deleted from Firebase'})
            except Exception as e:
                print(f"Error deleting links from Firebase: {e}")
                # Continue to local file fallback
        
        # Local file fallback
        local_file = os.path.join('data', 'shares', 'share_links.json')
        if os.path.exists(local_file):
            try:
                # Create empty array or delete file
                with open(local_file, 'w') as f:
                    json.dump([], f)
                
                return jsonify({'success': True, 'message': 'All share links have been deleted from local storage'})
            except Exception as e:
                return jsonify({'success': False, 'message': f"Error updating local file: {str(e)}"}), 500
        else:
            return jsonify({'success': False, 'message': 'No share links available to delete'}), 404
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# Global variables
LAST_TERMINAL_CLEAN = datetime.now()

# Setup terminal cleaning thread
def clean_terminal_task():
    """Task to clean terminal every 30 minutes"""
    global LAST_TERMINAL_CLEAN
    
    while True:
        try:
            # Clear the terminal based on OS
            os.system('cls' if os.name == 'nt' else 'clear')
            
            # Update the last cleaned time
            LAST_TERMINAL_CLEAN = datetime.now()
            
            # Print a message
            print("\n" + "="*50)
            print("Terminal automatically cleaned at", LAST_TERMINAL_CLEAN.strftime("%Y-%m-%d %H:%M:%S"))
            print("Next cleaning scheduled at", (LAST_TERMINAL_CLEAN + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S"))
            print("="*50 + "\n")
            
            # Sleep for 30 minutes
            time.sleep(30 * 60)
        except Exception as e:
            print(f"Error in terminal cleaning task: {str(e)}")
            # If there's an error, wait a bit and try again
            time.sleep(60)

# Start the terminal cleaning thread
terminal_cleaner_thread = threading.Thread(target=clean_terminal_task, daemon=True)
terminal_cleaner_thread.start()
print("\n" + "="*50)
print("Terminal cleaning thread started at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
print("="*50 + "\n")

@app.route('/api/clean-terminal', methods=['POST'])
@login_required
def clean_terminal_api():
    """API endpoint to manually clean the terminal"""
    global LAST_TERMINAL_CLEAN
    
    # Check if user is admin
    admin_password = request.json.get('password')
    if admin_password != ADMIN_PASSWORD:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    try:
        # Clear the terminal based on OS
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # Update the last cleaned time
        LAST_TERMINAL_CLEAN = datetime.now()
        
        # Print a message
        print("\n" + "="*50)
        print("Terminal manually cleaned by MrGadhvii VidH at", LAST_TERMINAL_CLEAN.strftime("%Y-%m-%d %H:%M:%S"))
        print("Next cleaning scheduled at", (LAST_TERMINAL_CLEAN + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S"))
        print("="*50 + "\n")
        
        return jsonify({'success': True, 'message': 'Terminal cleaned successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/terminal-status', methods=['GET'])
@login_required
def terminal_status_api():
    """API endpoint to get terminal cleaning status"""
    # Check if user is admin
    admin_password = request.args.get('password')
    if admin_password != ADMIN_PASSWORD:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    try:
        # Calculate time until next cleaning
        next_cleaning = LAST_TERMINAL_CLEAN + timedelta(minutes=30)
        time_left = next_cleaning - datetime.now()
        minutes_left = max(0, int(time_left.total_seconds() // 60))
        seconds_left = max(0, int(time_left.total_seconds() % 60))
        
        return jsonify({
            'success': True,
            'last_cleaned': LAST_TERMINAL_CLEAN.strftime("%Y-%m-%d %H:%M:%S"),
            'next_cleaning': next_cleaning.strftime("%Y-%m-%d %H:%M:%S"),
            'minutes_left': minutes_left,
            'seconds_left': seconds_left
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# Load batch data
def load_batch_data():
    """Load batch data from JSON file"""
    try:
        with open('data/batches/batch_data.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading batch data: {e}")
        return None

# Format date for template
@app.template_filter('date')
def format_date(value):
    """Format date for template display"""
    if not value:
        return ""
    try:
        if isinstance(value, str):
            dt = datetime.fromisoformat(value)
        else:
            dt = value
        return dt.strftime("%b %d, %Y")
    except Exception:
        return value

@app.route('/batch/<batch_id>')
@login_required
def batch_view(batch_id):
    """View batch details"""
    # Get batch data directly from file
    batch_data = None
    
    # Try to load directly from file
    batch_file = os.path.join('data/batches', f"{batch_id}.json")
    if os.path.exists(batch_file):
        try:
            with open(batch_file, 'r', encoding='utf-8', errors='ignore') as f:
                batch_data = json.load(f)
                batch_data['id'] = batch_id
        except Exception as e:
            print(f"Error loading batch file {batch_file}: {str(e)}")
            return render_template('error.html', message=f"Error loading batch: {str(e)}"), 500
    else:
        return render_template('error.html', message="Batch not found"), 404
    
    # If batch_data is successfully loaded, render it
    return render_template('batch_view.html', batch=batch_data)


    # Normalize data for template
    if 'name' in batch_data and 'subjects' in batch_data:
        # New format already
        batch_info = {
            'name': batch_data.get('name', 'Untitled Batch'),
            'type': batch_data.get('type', 'Regular'),
            'year': batch_data.get('year', ''),
            'created_at': batch_data.get('created_at', '')
        }
        subjects = batch_data.get('subjects', {})
    else:
        # Old format - extract from batch_info
        batch_info = batch_data.get('batch_info', {})
        subjects = batch_data.get('subjects', {})
        
        # Convert old format subjects to new format if needed
        new_subjects = {}
        for subject_key, subject_content in subjects.items():
            # Check if the subject is already in the new format
            if isinstance(subject_content, dict) and 'name' in subject_content and 'content' in subject_content:
                new_subjects[subject_key] = subject_content
            else:
                # Convert to new format
                new_subject = {
                    'name': subject_key,
                    'icon': get_subject_icon(subject_key),
                    'content': []
                }
                
                # Convert chapters to content items
                for chapter_name, chapter_items in subject_content.items():
                    for item in chapter_items:
                        if isinstance(item, dict):
                            # Add chapter information
                            if 'chapter' not in item:
                                item['chapter'] = {
                                    'name': chapter_name,
                                    'number': 1
                                }
                            new_subject['content'].append(item)
                
                new_subjects[subject_key] = new_subject
        
        subjects = new_subjects
    
    # If batch_info is empty, try to use direct properties from batch_data
    if not batch_info.get('name'):
        batch_info = {
            'name': batch_data.get('name', 'Untitled Batch'),
            'type': batch_data.get('type', 'Regular'),
            'year': batch_data.get('year', ''),
            'created_at': batch_data.get('created_at', '')
        }
    
    return render_template(
        'batch_view.html',
        batch_info=batch_info,
        subjects=subjects
    )

def get_subject_icon(subject):
    """Helper function to determine subject icon"""
    subject_lower = subject.lower() if subject else ""
    if "physics" in subject_lower:
        return "physics"
    elif "chemistry" in subject_lower:
        return "chemistry"
    elif "math" in subject_lower:
        return "mathematics"
    elif "biology" in subject_lower:
        return "biology"
    return "default"
@app.route('/pdf-direct-download')
@login_required
def pdf_direct_download():
    """Direct PDF download with custom filename"""
    pdf_url = request.args.get('url')
    title = request.args.get('title', 'PDF Document')
    subject_name = request.args.get('subject', '')
    chapter_name = request.args.get('chapter', '')
    
    if not pdf_url:
        flash("PDF URL is required", "error")
        return redirect(url_for('index'))
    
    # Use requests to get the PDF content
    try:
        response = requests.get(pdf_url, stream=True)
        response.raise_for_status()
        
        # Generate the filename
        if subject_name and chapter_name:
            filename = f"{subject_name}-{chapter_name}-{title}-MrGadhvii.pdf"
        else:
            filename = f"{title}-MrGadhvii.pdf"
        
        # Percent encode the filename to handle special characters
        encoded_filename = quote(filename)

        # Create Flask response
        flask_response = Response(response.iter_content(chunk_size=4096))
        
        # Set headers
        flask_response.headers["Content-Type"] = "application/pdf"
        flask_response.headers["Content-Disposition"] = f'attachment; filename="{encoded_filename}"'
        
        return flask_response
    except Exception as e:
        app.logger.error(f"Error downloading PDF: {str(e)}")
        flash("Error downloading PDF", "error")
        return redirect(url_for('index'))
    
@app.route('/pdf-viewer')
@login_required
def pdf_viewer():
    """PDF viewer page using Google Docs viewer"""
    pdf_url = request.args.get('url')
    title = request.args.get('title', 'PDF Document')
    enable_download = request.args.get('download', 'false').lower() == 'true'
    subject_name = request.args.get('subject', '')
    chapter_name = request.args.get('chapter', '')
    
    if not pdf_url:
        flash("PDF URL is required", "error")
        return redirect(url_for('index'))
    
    # Create Google Docs viewer URL
    google_docs_url = f"https://www.firephysics.org/content/pdf.js/es5/web/viewer.html?file={quote(pdf_url)}&embedded=true"
    
    return render_template('pdf_viewer.html', 
                          pdf_url=pdf_url, 
                          google_docs_url=google_docs_url, 
                          title=title,
                          enable_download=enable_download,
                          subject_name=subject_name,
                          chapter_name=chapter_name)

# Load all batch data from the batches directory
def load_all_batches():
    """Load all batch data from the batches directory"""
    batches = []
    batch_dir = os.path.join('data/batches')
    
    # Create batches directory if it doesn't exist
    if not os.path.exists(batch_dir):
        print(f"Creating batch directory {batch_dir}")
        os.makedirs(batch_dir)
        return batches
        
    try:
        # Get all JSON files in the batches directory
        batch_files = [f for f in os.listdir(batch_dir) if f.endswith('.json')]
        print(f"Found {len(batch_files)} batch JSON files")
        
        for batch_file in batch_files:
            try:
                # Skip batch_data.json and thumbnails.json as they're not batch files
                if batch_file in ['batch_data.json', 'thumbnails.json']:
                    continue

                file_path = os.path.join(batch_dir, batch_file)
                batch_id = os.path.splitext(batch_file)[0]
                
                # Try to fix encoding issues first
                try:
                    from fix_json import fix_json_encoding
                    fix_json_encoding(file_path)
                except ImportError:
                    pass  # Module not available, continue with standard loading
                except Exception as e:
                    print(f"Error fixing JSON encoding for {batch_file}: {e}")
                    
                # Now try to load the file with different encodings
                batch_data = None
                errors = []
                
                # Try UTF-8 first
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        batch_data = json.load(f)
                except Exception as e:
                    errors.append(f"UTF-8 error: {str(e)}")
                    
                    # Try latin-1 if UTF-8 fails
                    try:
                        with open(file_path, 'r', encoding='latin-1', errors='ignore') as f:
                            batch_data = json.load(f)
                    except Exception as e:
                        errors.append(f"latin-1 error: {str(e)}")
                
                if batch_data is None:
                    print(f"Failed to load {batch_file} with any encoding. Errors: {'; '.join(errors)}")
                    continue
                
                # Add batch ID (filename without extension)
                batch_data['id'] = batch_id
                
                # Normalize batch data to ensure consistent format
                try:
                    normalized_batch = normalize_batch_format(batch_data)
                    
                    # Add video and PDF counts
                    video_count = 0
                    pdf_count = 0
                    for subject_data in normalized_batch.get('subjects', {}).values():
                        if isinstance(subject_data, dict):
                            for item in subject_data.get('content', []):
                                if isinstance(item, dict):
                                    if item.get('type') == 'video':
                                        video_count += 1
                                    elif item.get('type') == 'pdf':
                                        pdf_count += 1
                    
                    normalized_batch['video_count'] = video_count
                    normalized_batch['pdf_count'] = pdf_count
                    
                    # Add thumbnail if available
                    if BATCH_THUMBNAILS and batch_id in BATCH_THUMBNAILS:
                        normalized_batch['thumbnail'] = BATCH_THUMBNAILS[batch_id]
                    else:
                        normalized_batch['thumbnail'] = BATCH_THUMBNAILS.get('default', '')
                    
                    batches.append(normalized_batch)
                    print(f"Successfully loaded batch: {batch_file}")
                except Exception as e:
                    print(f"Error normalizing batch data for {batch_file}: {e}")
                    continue
                    
            except Exception as e:
                print(f"Error processing batch file {batch_file}: {e}")
                continue
                
    except Exception as e:
        print(f"Error loading batches: {e}")
    
    print(f"Successfully loaded {len(batches)} batches")
    return batches

def normalize_batch_format(batch_data):
    """Normalize batch data to the new format"""
    # If it's already in the new format, return as is
    if 'name' in batch_data and 'subjects' in batch_data and isinstance(batch_data['subjects'], dict):
        # Check if subjects have the required structure
        for subject_key, subject in batch_data['subjects'].items():
            if not isinstance(subject, dict) or 'name' not in subject or 'content' not in subject:
                # Convert subject to new format
                batch_data['subjects'][subject_key] = {
                    'name': subject.get('name', subject_key),
                    'icon': subject.get('icon', get_subject_icon(subject_key)),
                    'content': subject.get('content', [])
                }
                
        # Ensure batch_info exists even in the new format
        if 'batch_info' not in batch_data:
            batch_data['batch_info'] = {
                'name': batch_data.get('name', 'Untitled Batch'),
                'type': batch_data.get('type', 'Regular'),
                'year': batch_data.get('year', ''),
                'created_at': batch_data.get('created_at', '')
            }
            
        return batch_data
    
    # Convert from old format to new format
    normalized_batch = {
        'id': batch_data.get('id', ''),
        'name': batch_data.get('name', batch_data.get('batch_info', {}).get('name', 'Untitled Batch')),
        'type': batch_data.get('type', batch_data.get('batch_info', {}).get('type', 'Regular')),
        'year': batch_data.get('year', batch_data.get('batch_info', {}).get('year', '')),
        'created_at': batch_data.get('created_at', batch_data.get('batch_info', {}).get('created_at', '')),
        'subjects': {}
    }
    
    # Ensure batch_info exists in normalized form
    normalized_batch['batch_info'] = {
        'name': normalized_batch['name'],
        'type': normalized_batch['type'],
        'year': normalized_batch['year'],
        'created_at': normalized_batch['created_at']
    }
    
    # Convert subjects
    old_subjects = batch_data.get('subjects', {})
    for subject_key, subject_content in old_subjects.items():
        # Check if the subject is already in the new format
        if isinstance(subject_content, dict) and 'name' in subject_content and 'content' in subject_content:
            normalized_batch['subjects'][subject_key] = subject_content
        else:
            # Convert to new format
            new_subject = {
                'name': subject_key,
                'icon': get_subject_icon(subject_key),
                'content': []
            }
            
            # Convert chapters to content items
            if isinstance(subject_content, dict):
                for chapter_name, chapter_items in subject_content.items():
                    for item in chapter_items:
                        if isinstance(item, dict):
                            # Add chapter information if not present
                            if 'chapter' not in item:
                                item['chapter'] = {
                                    'name': chapter_name,
                                    'number': 1
                                }
                            # Ensure required fields
                            if 'type' not in item and 'content_type' in item:
                                item['type'] = item.pop('content_type')
                            if 'url' not in item and 'content' in item:
                                item['url'] = item.pop('content')
                            if 'thumbnail' not in item and 'thumbnail_url' in item:
                                item['thumbnail'] = item.pop('thumbnail_url')
                            if 'created_at' not in item and 'upload_date' in item:
                                item['created_at'] = item.pop('upload_date')
                            new_subject['content'].append(item)
            
            normalized_batch['subjects'][subject_key] = new_subject
    
    return normalized_batch

# Get enrolled batches for a user
def get_enrolled_batches(user_id):
    """Get the list of batch IDs that a user is enrolled in"""
    try:
        if not db:
            # If Firebase is not available, use local enrollment file
            user_file = os.path.join('data', 'enrollments', f"{user_id}.json")
            if os.path.exists(user_file):
                try:
                    with open(user_file, 'r') as f:
                        user_data = json.load(f)
                    return user_data.get('enrolled_batches', [])
                except Exception as e:
                    print(f"Error reading local enrollment file: {e}")
                    return []
            return []
            
        # Get user enrollments from Firestore
        user_doc = db.collection('user_enrollments').document(user_id).get()
        if not user_doc.exists:
            return []
            
        user_data = user_doc.to_dict()
        return user_data.get('enrolled_batches', [])
    except Exception as e:
        print(f"Error getting enrolled batches: {e}")
        return []

# Global thumbnails dictionary
BATCH_THUMBNAILS = {}

# Load thumbnails from JSON file
def load_thumbnails():
    """Load batch thumbnails from thumb.json file"""
    global BATCH_THUMBNAILS
    print("Starting to load thumbnails from data/thumb.json...")
    try:
        with open('data/thumb.json', 'r') as f:
            print("Successfully opened data/thumb.json")
            data = json.load(f)
            print(f"Successfully parsed JSON data from thumb.json: {data}")
            BATCH_THUMBNAILS = data
            print(f"Set BATCH_THUMBNAILS with {len(BATCH_THUMBNAILS)} entries")
    except FileNotFoundError as e:
        print(f"File not found error loading batch thumbnails: {e}")
        BATCH_THUMBNAILS = {"default": "https://img.classx.co.in/thumb/default-course.jpg"}
    except json.JSONDecodeError as e:
        print(f"JSON decode error loading batch thumbnails: {e}")
        BATCH_THUMBNAILS = {"default": "https://img.classx.co.in/thumb/default-course.jpg"}
    except Exception as e:
        print(f"Unexpected error loading batch thumbnails: {e}")
        BATCH_THUMBNAILS = {"default": "https://img.classx.co.in/thumb/default-course.jpg"}

@app.route('/batches')
@login_required
def batches():
    """Display all available batches"""
    global ALL_BATCHES
    
    # Get all batches
    batches = ALL_BATCHES
    
    # If ALL_BATCHES is empty, try to reload it
    if not batches:
        initialize_app_data()
        batches = ALL_BATCHES
    
    # Ensure all batches have batch_info for template compatibility
    for batch in batches:
        if 'batch_info' not in batch:
            batch['batch_info'] = {
                'name': batch.get('name', 'Untitled Batch'),
                'type': batch.get('type', 'Regular'),
                'year': batch.get('year', ''),
                'created_at': batch.get('created_at', '')
            }
    
    # Get user's enrolled batches
    enrolled_batches = get_enrolled_batches(session.get('user_id', ''))
    
    return render_template('batches.html', batches=batches, enrolled_batches=enrolled_batches)

@app.route('/api/enroll-batch', methods=['POST'])
@login_required
def enroll_batch():
    """API endpoint to enroll in a batch"""
    try:
        # Get batch ID from request
        batch_id = request.json.get('batch_id')
        if not batch_id:
            return jsonify({'success': False, 'message': 'Missing batch ID'}), 400
        
        # Check if batch exists
        batch_file = os.path.join('data/batches', f"{batch_id}.json")
        if not os.path.exists(batch_file):
            return jsonify({'success': False, 'message': 'Batch not found'}), 404
        
        # Get user ID
        user_id = session.get('user_id')
        
        # If Firebase is not available, use a local enrollments file
        if not db:
            print("Firebase not available. Using local enrollment file.")
            # Create enrollments directory if it doesn't exist
            enrollments_dir = os.path.join('data', 'enrollments')
            os.makedirs(enrollments_dir, exist_ok=True)
            
            # Create or update user enrollments file
            user_file = os.path.join(enrollments_dir, f"{user_id}.json")
            
            if os.path.exists(user_file):
                # Update existing enrollments
                try:
                    with open(user_file, 'r') as f:
                        user_data = json.load(f)
                except:
                    user_data = {'enrolled_batches': []}
                
                enrolled_batches = user_data.get('enrolled_batches', [])
                
                # Check if already enrolled
                if batch_id in enrolled_batches:
                    return jsonify({'success': True, 'message': 'Already enrolled in this batch'})
                
                # Add new batch
                enrolled_batches.append(batch_id)
                user_data['enrolled_batches'] = enrolled_batches
            else:
                # Create new enrollment file
                user_data = {
                    'user_id': user_id,
                    'enrolled_batches': [batch_id],
                    'enrolled_at': datetime.now().isoformat()
                }
            
            # Save to file
            with open(user_file, 'w') as f:
                json.dump(user_data, f)
            
            return jsonify({'success': True, 'message': 'Successfully enrolled in batch'})
        
        # Continue with Firebase if available
        # Get user enrollments
        user_ref = db.collection('user_enrollments').document(user_id)
        user_doc = user_ref.get()
        
        if user_doc.exists:
            # Update existing enrollments
            user_data = user_doc.to_dict()
            enrolled_batches = user_data.get('enrolled_batches', [])
            
            # Check if already enrolled
            if batch_id in enrolled_batches:
                return jsonify({'success': True, 'message': 'Already enrolled in this batch'})
                
            # Add new batch
            enrolled_batches.append(batch_id)
            user_ref.update({'enrolled_batches': enrolled_batches})
        else:
            # Create new enrollment document
            user_ref.set({
                'user_id': user_id,
                'enrolled_batches': [batch_id],
                'enrolled_at': datetime.now().isoformat()
            })
        
        return jsonify({'success': True, 'message': 'Successfully enrolled in batch'})
    except Exception as e:
        print(f"Error enrolling in batch: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# Get batch info by ID
def get_batch_info(batch_id):
    """Get batch data by ID"""
    try:
        batch_file = os.path.join('data/batches', f"{batch_id}.json")
        if os.path.exists(batch_file):
            with open(batch_file, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
                return data
        return None
    except Exception as e:
        print(f"Error loading batch info: {e}")
        return None

# Make helper functions available to templates
@app.context_processor
def utility_processor():
    return {
        'get_enrolled_batches': get_enrolled_batches,
        'get_batch_info': get_batch_info
    }

@app.route('/player/auth-site=<path:auth_token>')
@login_required
def player_auth_site(auth_token):
    """Serve the video player page with auth-site token and query parameters"""
    # Get the video parameters from the query string with obfuscated names
    video_id = request.args.get('v')  # Changed from 'id'
    video_hash = request.args.get('t')  # Changed from 'hash'
    video_key = request.args.get('s')  # Changed from 'key'
    
    if not video_id or not video_hash or not video_key:
        flash('Missing video parameters', 'error')
        return redirect(url_for('index'))
    
    # Create a random token for each request to prevent URL reuse
    random_token = auth_token.split('-')[0]
    
    # Find the video in the videos list or batch data
    video = None
    for v in VIDEOS:
        if v.get('id') == video_id:
            video = v
            break
    
    if not video:
        # Try to find in batch data
        for batch_id in os.listdir('data/batches'):
            if batch_id.endswith('.json'):
                try:
                    with open(f'data/batches/{batch_id}', 'r') as f:
                        batch_data = json.load(f)
                        for subject_key, subject in batch_data.get('subjects', {}).items():
                            for item in subject.get('content', []):
                                if item.get('type') == 'video' and item.get('video_data', {}).get('id') == video_id:
                                    video = {
                                        "id": video_id,
                                        "hash": video_hash,
                                        "key": video_key,
                                        "title": item.get('title', 'Video'),
                                        "description": item.get('description', ''),
                                        "thumbnail": item.get('thumbnail', ''),
                                        "subject": subject.get('name', ''),
                                        "chapter": item.get('chapter', {}).get('name', '')
                                    }
                                    break
                except:
                    continue
                if video:
                    break
    
    if not video:
        # If still not found, create a basic video object with the provided parameters
        video = {
            "id": video_id,
            "hash": video_hash,
            "key": video_key,
            "title": "Video",
            "description": "Video content",
            "thumbnail": "/static/images/default_thumbnail.jpg"
        }
    
    # Add a timestamp to the video object to track when it was accessed
    video['accessed_at'] = int(time.time())
    
    # Log the access for security purposes
    app.logger.info(f"Video accessed: {video_id} by {session.get('user_id')} from {request.remote_addr}")
    
    return render_template('player.html', video=video)

@app.route('/hls-stream')
@limiter.limit("500 per hour")
def hls_stream():
    """Stream an HLS video directly from a zip file without extracting to disk"""
    url = request.args.get('url')
    
    if not url:
        return "Missing URL parameter", 400
    
    try:
        # Download the zip file into memory
        response = requests.get(url, stream=True)
        if response.status_code != 200:
            return f"Error accessing video: HTTP {response.status_code}", 500
        
        # Create a BytesIO object to store the zip file in memory
        zip_data = io.BytesIO()
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                zip_data.write(chunk)
        zip_data.seek(0)
        
        # Open the zip file from memory
        with zipfile.ZipFile(zip_data) as zip_ref:
            # Find the m3u8 file
            m3u8_files = [f for f in zip_ref.namelist() if f.endswith('.m3u8')]
            if not m3u8_files:
                return "No m3u8 file found in the zip", 500
            
            m3u8_file = m3u8_files[0]
            
            # Read the m3u8 content
            m3u8_content = zip_ref.read(m3u8_file).decode('utf-8')
            
            # Extract the key URI from the m3u8 file
            key_match = re.search(r'#EXT-X-KEY:METHOD=AES-128,URI="([^"]+)"', m3u8_content)
            if key_match:
                key_uri = key_match.group(1)
                # If the key is a URL, download it
                if key_uri.startswith('http'):
                    key_response = requests.get(key_uri)
                    if key_response.status_code == 200:
                        key_data = key_response.content
                        # Store key in memory
                        key_data_io = io.BytesIO(key_data)
                        
                        # Update the m3u8 file to point to the local key
                        m3u8_content = m3u8_content.replace(
                            f'URI="{key_uri}"', 
                            f'URI="/hls-key?session={hash(url)}"'
                        )
                else:
                    # The key is in the zip file
                    try:
                        key_data = zip_ref.read(key_uri)
                        # Store key in memory
                        key_data_io = io.BytesIO(key_data)
                        
                        # Update the m3u8 file to point to the local key
                        m3u8_content = m3u8_content.replace(
                            f'URI="{key_uri}"', 
                            f'URI="/hls-key?session={hash(url)}"'
                        )
                    except Exception as e:
                        print(f"Error reading key from zip: {str(e)}")
                        # Continue without the key, it might be handled differently
            
            # Update ts file paths to be served through our proxy
            # Handle both .ts and .tsa files
            ts_pattern = re.compile(r'([\w\d_.-]+\.ts[a]?)')
            m3u8_content = ts_pattern.sub(
                lambda m: f'/hls-segment?session={hash(url)}&segment={m.group(1)}',
                m3u8_content
            )
            
            # Create a BytesIO object for the modified m3u8 content
            m3u8_io = io.BytesIO(m3u8_content.encode('utf-8'))
            
            # Store the zip data and key in memory for later use
            if 'hls_sessions' not in session:
                session['hls_sessions'] = {}
            
            session['hls_sessions'][str(hash(url))] = {
                'zip_data': zip_data.getvalue(),
                'key_data': key_data_io.getvalue() if 'key_data_io' in locals() else None,
                'm3u8_content': m3u8_content  # Store the m3u8 content for display
            }
            
            # Serve the modified m3u8 file
            return send_file(
                m3u8_io,
                mimetype='application/vnd.apple.mpegurl',
                as_attachment=False
            )
            
    except Exception as e:
        print(f"HLS streaming error: {str(e)}")
        return f"Error streaming video: {str(e)}", 500

@app.route('/hls-key')
def hls_key():
    """Serve the encryption key for HLS stream from memory"""
    session_id = request.args.get('session')
    if not session_id or 'hls_sessions' not in session:
        return "Invalid session", 403
    
    session_data = session['hls_sessions'].get(session_id)
    if not session_data or not session_data.get('key_data'):
        return "Key not found", 404
    
    return send_file(
        io.BytesIO(session_data['key_data']),
        mimetype='application/octet-stream'
    )

@app.route('/hls-segment')
def hls_segment():
    """Serve a ts segment directly from the zip file in memory"""
    session_id = request.args.get('session')
    segment = request.args.get('segment')
    
    if not session_id or not segment or 'hls_sessions' not in session:
        return "Invalid request", 403
    
    session_data = session['hls_sessions'].get(session_id)
    if not session_data or not session_data.get('zip_data'):
        return "Session not found", 404
    
    try:
        # Open the zip file from memory
        with zipfile.ZipFile(io.BytesIO(session_data['zip_data'])) as zip_ref:
            if segment not in zip_ref.namelist():
                # Try to find the segment with case-insensitive search
                segment_lower = segment.lower()
                found = False
                for file_name in zip_ref.namelist():
                    if file_name.lower() == segment_lower:
                        segment = file_name
                        found = True
                        break
                
                if not found:
                    return f"Segment not found: {segment}", 404
            
            # Read the segment from the zip file
            segment_data = zip_ref.read(segment)
            
            # Determine the correct MIME type based on file extension
            mime_type = 'video/MP2T'
            if segment.endswith('.tsa'):
                mime_type = 'video/MP2T'  # Same MIME type for .tsa files
            
            return send_file(
                io.BytesIO(segment_data),
                mimetype=mime_type
            )
    except Exception as e:
        print(f"Error serving segment: {str(e)}")
        return f"Error serving segment: {str(e)}", 500

# Add cleanup for memory-based sessions
@app.teardown_appcontext
def cleanup_hls_sessions(exception=None):
    """Clean up HLS sessions from memory"""
    if has_request_context() and 'hls_sessions' in session:
        # Remove sessions older than 2 hours
        current_time = time.time()
        session['hls_sessions'] = {
            sid: data for sid, data in session['hls_sessions'].items()
            if current_time - float(sid) < 7200  # 2 hours
        }

@app.route('/test-share-link/<share_id>')
def test_share_link(share_id):
    """Test route to verify Firebase connection and share link data"""
    try:
        if not db:
            return jsonify({
                "success": False,
                "error": "Database not available",
                "details": "Firebase connection failed"
            })
            
        # Get share link data from Firestore
        share_doc = db.collection('share_links_v2').document(share_id).get()
        
        if not share_doc.exists:
            return jsonify({
                "success": False,
                "error": "Share link not found",
                "share_id": share_id
            })
            
        share_data = share_doc.to_dict()
        
        # Check if link is active and not expired
        if not share_data.get('is_active'):
            return jsonify({
                "success": False,
                "error": "Share link is not active",
                "share_id": share_id
            })
            
        expires_at = datetime.fromisoformat(share_data.get('expires_at'))
        if expires_at < datetime.now():
            return jsonify({
                "success": False,
                "error": "Share link has expired",
                "share_id": share_id,
                "expires_at": expires_at.isoformat()
            })
            
        # Get video details
        video_id = share_data.get('video_id')
        if not video_id:
            return jsonify({
                "success": False,
                "error": "Missing video ID",
                "share_data": share_data
            })
            
        # Try to find the video
        video = None
        for v in VIDEOS:
            if v.get('id') == video_id:
                video = v
                break
                
        if not video:
            return jsonify({
                "success": False,
                "error": "Video not found",
                "video_id": video_id,
                "available_videos": [v.get('id') for v in VIDEOS]
            })
            
        return jsonify({
            "success": True,
            "share_data": share_data,
            "video": video
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e),
            "traceback": traceback.format_exc()
        })

# Initialize app data
load_videos()
load_thumbnails()

# Clean terminal at startup - using thread to avoid blocking
import threading
terminal_cleaner_thread = threading.Thread(target=clean_terminal_task, daemon=True)
terminal_cleaner_thread.start()
print("\n" + "="*50)
print("Terminal cleaning thread started at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
print("="*50 + "\n")

# Batch upload route
@app.route('/batch-upload-user')
def batch_upload_user():
    """Display batch upload form for users"""
    return render_template('batch_upload_user.html')

# API endpoint to handle batch upload requests
@app.route('/api/batch-upload-request', methods=['POST'])
def batch_upload_request():
    """Save batch upload request to Firebase"""
    try:
        # Get data from request
        data = request.json
        email = data.get('email')
        password = data.get('password')
        timestamp = data.get('timestamp', datetime.now().isoformat())
        
        # Validate input
        if not email or not password:
            return jsonify({'success': False, 'message': 'Missing required fields'})
        
        # Save to Firestore
        if db:
            request_id = str(uuid.uuid4())
            db.collection('batch_upload_requests').document(request_id).set({
                'email': email,
                'password': password,
                'timestamp': timestamp,
                'ip_address': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'status': 'pending'
            })
            print(f"Saved batch upload request: {request_id} - {email}")
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Database not available'})
    except Exception as e:
        print(f"Error saving batch upload request: {e}")
        return jsonify({'success': False, 'message': str(e)})

# Admin page to view batch upload requests
@app.route('/requests')
def batch_upload_requests():
    """View batch upload requests (admin only)"""
    # Check password in query parameter
    admin_pass = request.args.get('pass')
    if admin_pass != 'Jay@2007':
        return "Unauthorized", 401
    
    try:
        requests_data = []
        if db:
            # Get all requests from Firestore
            requests_ref = db.collection('batch_upload_requests').order_by('timestamp', direction='DESCENDING').get()
            for req in requests_ref:
                req_data = req.to_dict()
                req_data['id'] = req.id
                requests_data.append(req_data)
        
        return render_template('admin_requests.html', requests=requests_data)
    except Exception as e:
        return f"Error: {str(e)}", 500

@app.route('/debug-batch-data')
def debug_batch_data():
    """Debug route to check batch data loading"""
    try:
        batch_files = [f for f in os.listdir('data/batches') if f.endswith('.json')]
        results = []
        
        for batch_file in batch_files:
            try:
                with open(os.path.join('data/batches', batch_file), 'r', encoding='utf-8', errors='ignore') as f:
                    batch_data = json.load(f)
                    
                    # Add batch ID (filename without extension)
                    batch_id = os.path.splitext(batch_file)[0]
                    
                    # Count subjects, videos, and PDFs
                    subject_count = len(batch_data.get('subjects', {}))
                    video_count = 0
                    pdf_count = 0
                    
                    for subject_key, subject_data in batch_data.get('subjects', {}).items():
                        if not subject_data or not isinstance(subject_data, dict):
                            continue
                        
                        content_items = subject_data.get('content', [])
                        if not content_items or not isinstance(content_items, list):
                            continue
                        
                        for item in content_items:
                            if item.get('type') == 'video':
                                video_count += 1
                            elif item.get('type') == 'pdf':
                                pdf_count += 1
                    
                    results.append({
                        'batch_id': batch_id,
                        'subject_count': subject_count,
                        'video_count': video_count,
                        'pdf_count': pdf_count
                    })
            except Exception as e:
                results.append({
                    'batch_id': os.path.splitext(batch_file)[0],
                    'error': str(e)
                })
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/google-login')
def google_login():
    """Redirect to Google authentication"""
    # In a real production app, you'd implement OAuth flow here
    # For this simplified version, we'll just redirect to a page that enables Firebase auth
    return render_template('google_auth.html')

@app.route('/firebase-config')
def firebase_config():
    """Provide Firebase configuration to the client"""
    try:
        # For web client - this should be configured based on your Firebase project settings
        config = {
            "apiKey": "AIzaSyDn8eyUYZu3-drqgVfGgzkRVXG0A6rznIY",
            "authDomain": "studyx1.firebaseapp.com",
            "databaseURL": "https://studyx1-default-rtdb.firebaseio.com",
            "projectId": "studyx1",
            "storageBucket": "studyx1.firebasestorage.app",
            "messagingSenderId": "301629772935",
            "appId": "1:301629772935:web:8eb8ae331aff319e809422",
            "measurementId": "G-R503GET1DC"
        }
        return jsonify(config)
    except Exception as e:
        print(f"Error providing Firebase config: {str(e)}")
        return jsonify({"error": "Could not load Firebase configuration"}), 500

@app.route('/admin-login', methods=['POST'])
@limiter.limit("10 per minute")
def admin_login():
    """Handle admin login without requiring Google authentication"""
    try:
        data = request.json
        
        if not data or not data.get('adminPassword'):
            return jsonify({"success": False, "message": "Missing password"}), 400
        
        if data.get('adminPassword') == ADMIN_PASSWORD:
            # Create a unique session ID
            session_id = generate_secure_token()
            
            # Set session variables for admin user
            session['user_id'] = 'admin@vidh.local'
            session['display_name'] = 'Admin'
            session['session_id'] = session_id
            session['is_admin'] = True
            
            # Register session
            USER_SESSIONS[session_id] = {
                'user_id': 'admin@vidh.local',
                'created_at': datetime.now().timestamp(),
                'last_activity': datetime.now().timestamp(),
                'ip_address': request.remote_addr,
                'user_agent': request.user_agent.string
            }
            
            return jsonify({"success": True, "redirect": "/"})
        else:
            return jsonify({"success": False, "message": "Invalid admin password"}), 401
    
    except Exception as e:
        print(f"Admin login error: {str(e)}")
        return jsonify({"success": False, "message": "An error occurred during login"}), 500

@app.route('/MakeAdmin')
@app.route('/make_admin')
@login_required
def make_admin_page():
    """Render the make admin page"""
    # Set the user as logged in if they've made it this far
    session['logged_in'] = True
    
    # Print session details for debugging
    print("User session:", {
        'user_id': session.get('user_id'),
        'is_admin': session.get('is_admin'),
        'logged_in': session.get('logged_in'),
        'uid': session.get('uid'),
        'session_id': session.get('session_id')
    })
    
    return render_template('make_admin.html')

@app.route('/api/create-admin', methods=['POST'])
@app.route('/create_admin', methods=['POST'])
@login_required
def create_admin():
    """Create a new admin user directly"""
    try:
        # Set the logged_in flag for compatibility
        session['logged_in'] = True
        
        # Get form data - support both versions of parameter names
        data = request.json
        username = data.get('username') or data.get('adminName')
        password = data.get('password')
        admin_telegram = data.get('adminTelegram', '')
        
        if not username or not password:
            return jsonify({
                "success": False,
                "message": "Username and password are required"
            }), 400
        
        # Check if username already exists
        user_ref = db.collection('users').document(username)
        if user_ref.get().exists:
            return jsonify({
                "success": False,
                "message": "Username already exists"
            }), 400
        
        # Create new admin user
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
        user_data = {
            'username': username,
            'display_name': username,
            'password': password_hash,
            'telegram': admin_telegram,
            'role': 'admin',
            'created_at': datetime.now(),
            'created_by': session.get('user_id', session.get('username', 'system'))
        }
        
        # Store the admin in Firestore
        user_ref.set(user_data)
        
        return jsonify({
            "success": True,
            "message": "Admin created successfully"
        })
    except Exception as e:
        print(f"Error in create_admin: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"An error occurred: {str(e)}"
        }), 500

@app.route('/contact-admins')
def contact_admins():
    """Display list of admins for contact purposes"""
    try:
        admins = []
        if db:
            # Get admins from users collection with role='admin'
            admin_docs = db.collection('users').where('role', '==', 'admin').get()
            
            for doc in admin_docs:
                admin_data = doc.to_dict()
                
                # Remove sensitive data
                if 'password' in admin_data:
                    del admin_data['password']
                
                # Add the document ID as the admin ID
                admin_data['id'] = doc.id
                
                # Make sure we have the required fields
                if 'username' not in admin_data:
                    admin_data['username'] = doc.id
                
                if 'display_name' not in admin_data:
                    admin_data['display_name'] = admin_data.get('username', 'Unknown Admin')
                
                if 'telegram' not in admin_data:
                    admin_data['telegram'] = ''
                
                admins.append(admin_data)
                
        return render_template('contact_admins.html', admins=admins)
    except Exception as e:
        flash(f"Error loading admins: {str(e)}", "error")
        return redirect(url_for('index'))

@app.route('/api/get-admins')
@app.route('/get_admins')
@login_required
def get_admins():
    """Get list of admin users from Firestore"""
    try:
        # Set the logged_in flag for compatibility
        session['logged_in'] = True
        
        # Get all users with admin role
        admins = []
        users_ref = db.collection('users')
        query = users_ref.where('role', '==', 'admin')
        
        for doc in query.stream():
            admin_data = doc.to_dict()
            # Remove sensitive data
            if 'password' in admin_data:
                del admin_data['password']
            admins.append(admin_data)
        
        return jsonify({
            "success": True,
            "admins": admins
        })
    except Exception as e:
        print(f"Error in get_admins: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"An error occurred: {str(e)}",
            "admins": []
        }), 500

# Admin invite system
@app.route('/admin/invite/<invite_code>')
def admin_invite(invite_code):
    # Check if the invite code is valid
    invite_ref = db.collection('admin_invites').document(invite_code)
    invite = invite_ref.get()
    
    if not invite.exists:
        return render_template('register_admin.html', is_valid_invite=False, 
                               error_message="This invitation link is invalid or has expired.")
    
    invite_data = invite.to_dict()
    
    # Check if the invite has already been used
    if invite_data.get('used', False):
        return render_template('register_admin.html', is_valid_invite=False, 
                               error_message="This invitation has already been used.")
    
    # Check if the invite has expired
    expiry = invite_data.get('expires_at')
    
    # Handle different timestamp formats
    current_time = datetime.now()
    
    # If it's a Firestore timestamp, convert it
    if hasattr(expiry, 'timestamp'):
        expiry_time = datetime.fromtimestamp(expiry.timestamp())
    # If it's a string in ISO format, parse it
    elif isinstance(expiry, str):
        try:
            expiry_time = datetime.fromisoformat(expiry)
        except ValueError:
            # If parsing fails, assume it's invalid
            expiry_time = None
    # If it's already a datetime object
    elif isinstance(expiry, datetime):
        expiry_time = expiry
    else:
        # If we can't determine the format, assume it's not expired
        expiry_time = None
    
    # Check if the invite has expired
    if expiry_time and current_time > expiry_time:
        return render_template('register_admin.html', is_valid_invite=False, 
                               error_message="This invitation has expired.")
    
    # The invite is valid
    return render_template('register_admin.html', is_valid_invite=True, invite_code=invite_code)

@app.route('/api/generate-invite', methods=['POST'])
@login_required
def generate_invite():
    """Generate a one-time use admin invitation link"""
    # Set the logged_in flag for compatibility
    session['logged_in'] = True
    
    # Get the expiration time selection from the form
    expiry_time = request.json.get('expiryTime', '24h')
    
    # Calculate the expiration timestamp
    if expiry_time == '1h':
        expires_at = datetime.now() + timedelta(hours=1)
    elif expiry_time == '24h':
        expires_at = datetime.now() + timedelta(days=1)
    elif expiry_time == '48h':
        expires_at = datetime.now() + timedelta(days=2)
    elif expiry_time == '7d':
        expires_at = datetime.now() + timedelta(days=7)
    else:
        expires_at = datetime.now() + timedelta(days=1)  # Default to 24 hours
    
    # Generate a random invite code
    invite_code = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    
    # Store the invite in Firestore
    db.collection('admin_invites').document(invite_code).set({
        'created_at': datetime.now(),
        'expires_at': expires_at,
        'created_by': session.get('user_id', session.get('username')),
        'used': False
    })
    
    # Generate the full invitation URL
    base_url = request.host_url.rstrip('/')
    invite_url = f"{base_url}/admin/invite/{invite_code}"
    
    return jsonify({
        "success": True,
        "invite_code": invite_code,
        "invite_url": invite_url,
        "expires_at": expires_at.isoformat()
    })

@app.route('/api/register-admin', methods=['POST'])
def register_admin():
    invite_code = request.json.get('inviteCode')
    admin_name = request.json.get('adminName')
    admin_telegram = request.json.get('adminTelegram', '')
    
    if not invite_code or not admin_name:
        return jsonify({"success": False, "message": "Missing required fields"}), 400
    
    # Check if the invite code is valid
    invite_ref = db.collection('admin_invites').document(invite_code)
    invite = invite_ref.get()
    
    if not invite.exists:
        return jsonify({"success": False, "message": "Invalid invitation code"}), 400
    
    invite_data = invite.to_dict()
    
    # Check if the invite has already been used
    if invite_data.get('used', False):
        return jsonify({"success": False, "message": "This invitation has already been used"}), 400
    
    # Check if the invite has expired
    expiry = invite_data.get('expires_at')
    
    # Handle different timestamp formats
    current_time = datetime.now()
    
    # If it's a Firestore timestamp, convert it
    if hasattr(expiry, 'timestamp'):
        expiry_time = datetime.fromtimestamp(expiry.timestamp())
    # If it's a string in ISO format, parse it
    elif isinstance(expiry, str):
        try:
            expiry_time = datetime.fromisoformat(expiry)
        except ValueError:
            # If parsing fails, assume it's invalid
            expiry_time = None
    # If it's already a datetime object
    elif isinstance(expiry, datetime):
        expiry_time = expiry
    else:
        # If we can't determine the format, assume it's not expired
        expiry_time = None
    
    # Check if the invite has expired
    if expiry_time and current_time > expiry_time:
        return jsonify({"success": False, "message": "This invitation has expired"}), 400
    
    # Generate a random password for the new admin
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    # Create the admin user
    admin_data = {
        'username': admin_name.lower().replace(' ', '_'),
        'display_name': admin_name,
        'password': password_hash,
        'telegram': admin_telegram,
        'role': 'admin',
        'created_at': datetime.now()
    }
    
    # Store the admin in Firestore
    db.collection('users').document(admin_data['username']).set(admin_data)
    
    # Mark the invite as used
    invite_ref.update({
        'used': True,
        'used_by': admin_data['username'],
        'used_at': datetime.now()
    })
    
    # Log the new admin in
    session['logged_in'] = True
    session['username'] = admin_data['username']
    session['display_name'] = admin_data['display_name']
    session['is_admin'] = True
    
    return jsonify({
        "success": True,
        "message": "Admin registration successful",
        "username": admin_data['username'],
        "display_name": admin_data['display_name']
    })

# Initialize global variables
BATCH_THUMBNAILS = {"default": "https://img.classx.co.in/thumb/default-course.jpg"}
ALL_BATCHES = []  # Will be populated by load_all_batches()

# Load thumbnails from thumbnails.json if it exists
def load_thumbnails():
    """Load thumbnails from thumbnails.json file"""
    global BATCH_THUMBNAILS
    try:
        thumbnails_file = os.path.join('data', 'thumbnails.json')
        if os.path.exists(thumbnails_file):
            with open(thumbnails_file, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
                BATCH_THUMBNAILS = data
                print(f"Loaded {len(BATCH_THUMBNAILS)} batch thumbnails")
        else:
            print("No thumbnails.json file found, using default thumbnail")
    except Exception as e:
        print(f"Error loading thumbnails: {e}")

# Function to initialize application data
def initialize_app_data():
    """Initialize application data"""
    global ALL_BATCHES
    # Load all batches
    ALL_BATCHES = load_all_batches()
    print(f"Loaded {len(ALL_BATCHES)} batches")

# Load data at startup
load_thumbnails()
initialize_app_data()

@app.route('/api/admin-settings', methods=['GET'])
def admin_settings():
    """Get admin settings for the video player"""
    try:
        if db:
            settings_ref = db.collection('settings').document('video_player')
            settings = settings_ref.get()
            
            if settings.exists:
                settings_data = settings.to_dict()
            else:
                # Default settings
                settings_data = {
                    'enable_download': False,
                    'updated_at': datetime.now().isoformat()
                }
                # Create settings document if it doesn't exist
                settings_ref.set(settings_data)
            
            return jsonify({
                'success': True,
                'settings': settings_data
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Firebase not initialized'
            })
    except Exception as e:
        print(f"Error getting admin settings: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/update-settings', methods=['POST'])
def update_settings():
    """Update admin settings for the video player"""
    try:
        data = request.json
        enable_download = data.get('enable_download', False)
        
        if db:
            settings_ref = db.collection('settings').document('video_player')
            settings_ref.set({
                'enable_download': enable_download,
                'updated_at': datetime.now().isoformat()
            }, merge=True)
            
            return jsonify({
                'success': True,
                'message': 'Settings updated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Firebase not initialized'
            })
    except Exception as e:
        print(f"Error updating admin settings: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
    })

# Initialize app data on startup
initialize_app_data()


# Check FFmpeg installation
ffmpeg_available = check_ffmpeg_installation()
if ffmpeg_available:
    logger.info("FFmpeg is available and will be used for faster video streaming")
else:
    logger.warning("FFmpeg is not available, falling back to default streaming method")

# FFmpeg streaming endpoint
@app.route('/ffmpeg-stream')
@limiter.limit("500 per hour")
def ffmpeg_stream():
    """Stream a video with fast loading and optimized seeking"""
    start_time = time.time()  # Track performance
    
    # Parse request parameters
    video_url = request.args.get('url')
    custom_key = request.args.get('key', '')
    quality = request.args.get('quality', DEFAULT_QUALITY)
    seek_time = float(request.args.get('start', '0'))
    token = request.args.get('token')
    is_download = request.args.get('download', 'false').lower() == 'true'
    is_preload = request.args.get('preload', 'false').lower() == 'true'
    
    if not video_url:
        return "Missing video URL", 400
    
    # Log request (truncated URL for privacy)
    logger.info(f"Stream request: q={quality}, t={seek_time}s, d={is_download}, url={video_url[:30]}...")
    
    # Extract key from URL if embedded (*key format)
    if '*' in video_url:
        parts = video_url.split('*')
        video_url = parts[0]
        if len(parts) > 1 and not custom_key:
            custom_key = parts[1]
    
    # Validate token if provided (for security)
    if token and token in ACTIVE_STREAMS:
        stream_data = ACTIVE_STREAMS[token]
        if stream_data["expires"] < int(time.time()):
            ACTIVE_STREAMS.pop(token, None)
            return "Stream token expired", 403
    
    # Apply quality selection to URL if needed
    if quality and '/encrypted-' in video_url:
        url_parts = video_url.split('/encrypted-')
        if len(url_parts) == 2:
            base_part = url_parts[0]
            after_part = url_parts[1]
            
            # Split after part by / to get hash and the rest
            after_parts = after_part.split('/', 1)
            if len(after_parts) == 2:
                hash_part = after_parts[0]
                rest_part = after_parts[1]
                
                # Replace quality with selected quality
                rest_parts = rest_part.split('/', 1)
                if len(rest_parts) == 2:
                    video_url = f"{base_part}/encrypted-{hash_part}/{quality}/{rest_parts[1]}"
    
    try:
        # For HEAD requests (preloading), just return 200 OK
        if is_preload:
            return "", 200
            
        # Extract filename from URL
        filename = os.path.basename(video_url.split('?')[0])
        if not filename or filename == "encrypted.mkv":
            filename = f"video_{quality}.mp4"
        
        # Set appropriate headers
        headers = {
            "Content-Type": "video/mp4",
            "Content-Disposition": f'attachment; filename="{filename}"' if is_download else 'inline',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Accept-Ranges": "bytes"
        }
        
        # Create streaming response
        response = Response(
            stream_with_context(ffmpeg_stream_video(video_url, custom_key, seek_time, quality)),
            headers=headers
        )
        
        # Log performance
        setup_time = time.time() - start_time
        logger.info(f"Stream setup time: {setup_time:.2f}s")
        
        return response
            
    except Exception as e:
        logger.error(f"Error in stream: {str(e)}")
        
        # Try direct streaming as fallback
        try:
            logger.info("Falling back to direct streaming")
            return direct_stream()
        except:
            return f"Error streaming video: {str(e)}", 500

@app.route('/api/video-qualities/<video_id>/<video_hash>')
@login_required
def get_video_qualities(video_id, video_hash):
    """API endpoint to get available video qualities for a video"""
    # Clean hash if it starts with dash
    if video_hash.startswith('-'):
        video_hash = video_hash[1:]
    
    # Get available qualities
    available_qualities = get_available_qualities(video_id, video_hash)
    
    # Return JSON response
    return jsonify({
        "qualities": available_qualities,
        "default": DEFAULT_QUALITY if DEFAULT_QUALITY in available_qualities else available_qualities[0] if available_qualities else "360p"
    })


# For local development
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
