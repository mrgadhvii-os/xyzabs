FROM python:3.9

# Install FFmpeg
RUN apt-get update && apt-get install -y ffmpeg

# Set up your application
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .

# Run your application
CMD ["gunicorn", "-b", "0.0.0.0:8080", "app:app"]
