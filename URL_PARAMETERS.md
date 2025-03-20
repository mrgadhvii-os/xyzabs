# VidH URL Parameters and Special Routes

This document provides a comprehensive list of URL parameters and special routes available in the VidH application.

## Authentication Routes

- **/login** - The main login page with Google login and admin access options
- **/google-login** - Redirects to Google authentication
- **/firebase-login** - API endpoint for handling Firebase authentication
- **/admin-login** - API endpoint for admin login without Google
- **/logout** - Logs out the current user

## Admin Management

- **/MakeAdmin?pass=Jay@2007** - Special route to access the admin creation page (requires password)
- **/api/create-admin** - API endpoint to create a new admin in Firebase
- **/api/get-admins** - API endpoint to get the list of admins
- **/contact-admins** - Page displaying all admins with contact information

## Video Routes

- **/player/{video_index}** - Play a video by its index
- **/player/video/{video_id}** - Play a video by its ID
- **/player/v2/{video_id}** - Enhanced video player by video ID
- **/player/{auth_param}** - Play a video with an obfuscated URL parameter
- **/player/auth-site={auth_token}** - Play a video from an authorized site
- **/authorize-stream** - API endpoint to authorize video streaming
- **/stream** - Streaming endpoint for videos
- **/direct-stream** - Direct streaming endpoint without authentication
- **/hls-stream** - HLS streaming endpoint
- **/hls-key** - HLS encryption key endpoint
- **/hls-segment** - HLS segment endpoint

## Share Link Management

- **/generate-share-link** - API to generate a share link
- **/shared/{share_id}** - Access a shared video
- **/sharelinks** - Admin page to manage share links
- **/api/sharelinks/disable-all** - API to disable all share links
- **/api/sharelinks/delete-all** - API to delete all share links
- **/test-share-link/{share_id}** - Test a share link's validity

## Batch Management

- **/batches** - View all available batches
- **/batch/{batch_id}** - View specific batch details
- **/api/enroll-batch** - API to enroll in a batch
- **/batch-upload-user** - Page for users to request batch uploads
- **/api/batch-upload-request** - API to submit batch upload requests
- **/requests** - Admin view of batch upload requests

## Utility Routes

- **/profile-image/{user_id}** - Get a user's profile image
- **/api/clean-terminal** - API to clean the terminal logs
- **/api/terminal-status** - API to check terminal status
- **/pdf-viewer** - PDF viewer page
- **/firebase-config** - API to get Firebase configuration

## Debug Routes

- **/testurl** - Test URL generation
- **/secure-test/{auth_param}** - Test secure parameters
- **/debug-batch-data** - Debug batch data 