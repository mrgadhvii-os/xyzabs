# VidH - Secure Video Streaming Platform

VidH is a secure video streaming platform built with Flask that provides encrypted video delivery, user authentication, and content sharing capabilities. The platform is designed to protect video content while providing a seamless viewing experience.

## Features

- 🔒 Secure video streaming with encryption
- 👤 User authentication with Firebase
- 📱 Responsive video player with multiple quality options
- 🔗 Secure video sharing with expiration
- 📚 Batch-based content organization
- 🎨 Modern UI with custom styling
- 🛡️ Anti-piracy measures
- 📊 Admin dashboard for content management

## Tech Stack

- **Backend**: Python/Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **Database**: Firebase Firestore
- **Authentication**: Firebase Auth
- **Video Player**: Plyr.js
- **UI Framework**: Bootstrap 5
- **Icons**: Font Awesome
- **Rate Limiting**: Flask-Limiter

## Project Structure

```
VidH/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── firebase-service-account.json  # Firebase credentials
├── static/               # Static files
│   ├── css/             # Stylesheets
│   ├── js/              # JavaScript files
│   ├── images/          # Image assets
│   └── profile_images/  # User profile images
├── templates/           # HTML templates
│   ├── index.html       # Main dashboard
│   ├── login.html       # Login page
│   ├── player.html      # Video player
│   ├── shared_video.html # Shared video view
│   ├── batches.html     # Batch listing
│   ├── batch_view.html  # Individual batch view
│   ├── pdf_viewer.html  # PDF viewer
│   ├── share_links_admin.html # Admin dashboard
│   └── header.html      # Common header partial
└── data/               # Data files
    └── batches/        # Batch JSON files
        ├── batch_data.json
        └── [batch_name].json
```

## Setup Instructions

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/vidh.git
   cd vidh
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Firebase Setup**
   - Create a Firebase project
   - Enable Authentication and Firestore
   - Download service account key and save as `firebase-service-account.json`

5. **Environment Variables**
   Create a `.env` file with:
   ```
   SECRET_KEY=your_secret_key
   URL_SECRET=your_url_secret
   ```

6. **Run the application**
   ```bash
   python app.py
   ```

## Key Features Implementation

### Video Streaming
- Videos are encrypted and streamed securely
- Supports multiple quality options (360p, 480p, 720p)
- Implements anti-download measures
- Includes watermarking for content protection

### Authentication
- Firebase-based user authentication
- Session management with security features
- Remember me functionality
- Profile image handling

### Content Organization
- Batch-based content structure
- Subject categorization
- Support for both video and PDF content
- Dynamic content loading

### Sharing System
- Secure share link generation
- Link expiration management
- View tracking
- Admin controls for share management

## Security Features

- URL obfuscation
- Anti-debugging measures
- Rate limiting
- Session validation
- IP tracking
- User agent verification
- Secure cookie handling

## API Endpoints

- `/` - Main dashboard
- `/login` - Login page
- `/player/<video_id>` - Video player
- `/shared/<share_id>` - Shared video access
- `/batches` - Batch listing
- `/batch/<batch_id>` - Individual batch view
- `/generate-share-link` - Share link generation
- `/api/videos` - Video list API
- `/api/enroll-batch` - Batch enrollment API

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Plyr.js](https://github.com/sampotts/plyr) for the video player
- [Bootstrap](https://getbootstrap.com/) for the UI framework
- [Font Awesome](https://fontawesome.com/) for icons
- [Firebase](https://firebase.google.com/) for authentication and database

## Support

For support, email support@vidh.com or create an issue in the repository.

## Deployment to Vercel

This application is configured for deployment on Vercel. Follow these steps to deploy:

1. Install the Vercel CLI:
   ```
   npm i -g vercel
   ```

2. Login to Vercel:
   ```
   vercel login
   ```

3. Deploy to Vercel:
   ```
   vercel
   ```

## Deployment to Render (Recommended for Video Streaming)

Render is recommended for video streaming applications due to better handling of long-lived connections.

### One-Click Deployment

The easiest way to deploy to Render is using the render.yaml configuration:

1. Create a new web service in Render dashboard
2. Connect your GitHub repository
3. Render will automatically detect the render.yaml file and configure the deployment

### Manual Deployment

1. Create a new Web Service in your Render dashboard
2. Connect your GitHub repository
3. Use these settings:
   - Environment: Python 3
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`
   
4. Add the following environment variables:
   - `SECRET_KEY`: A secure random string
   - `ADMIN_PASSWORD`: Password for admin access
   - `URL_SECRET`: Secret for URL signing
   - `APP_URL`: Your Render app URL (e.g. https://vidh.onrender.com)
   - `FIREBASE_SERVICE_ACCOUNT`: JSON content of your firebase-service-account.json

### Anti-Sleep Features

The app includes built-in anti-sleep mechanisms to prevent Render's free tier from going inactive:

1. Auto-ping service that runs in the background
2. Health check endpoint at `/health`
3. Simple ping endpoint at `/ping`

You can also use an external service like UptimeRobot to ping your app periodically.

## Environment Variables

Make sure to set these environment variables:

- `SECRET_KEY`: A secure secret key for Flask
- `ADMIN_PASSWORD`: Password for admin access (currently defaults to "Jay@2007")
- `URL_SECRET`: Secret for URL signing/encryption
- `FIREBASE_SERVICE_ACCOUNT`: The contents of your firebase-service-account.json file (for Render/Vercel)
- `APP_URL`: The URL of your deployed application

## Firebase Configuration

1. Place your `firebase-service-account.json` file in the project root
2. If deploying to Render/Vercel, add the contents of this file as an environment variable named `FIREBASE_SERVICE_ACCOUNT` in JSON format

## Local Development

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   python app.py
   ``` 