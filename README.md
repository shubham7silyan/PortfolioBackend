# Portfolio Contact Form Backend

A Node.js backend server that handles contact form submissions with database storage and Gmail email notifications.

## Features

- ✅ Contact form data storage in MongoDB
- 📧 Automatic Gmail email notifications
- 🔒 Environment variable security
- 📊 RESTful API endpoints
- 🎨 Beautiful HTML email templates
- ⚡ Real-time form validation

## Setup Instructions

### 1. Install Dependencies

```bash
cd NodeJs
npm install
```

### 2. Configure Environment Variables

Update the `.env` file with your credentials:

```env
# Gmail Configuration
GMAIL_USER=shubham7silyan@gmail.com
GMAIL_APP_PASSWORD=your_gmail_app_password_here

# MongoDB Configuration
MONGODB_URI=mongodb://127.0.0.1:27017/portfolioDB

# Server Configuration
PORT=5050
```

### 3. Gmail App Password Setup

1. Go to your Google Account settings
2. Enable 2-Factor Authentication
3. Generate an App Password:
   - Go to Security > App passwords
   - Select "Mail" and your device
   - Copy the generated 16-character password
   - Paste it in the `.env` file as `GMAIL_APP_PASSWORD`

### 4. Start MongoDB

Make sure MongoDB is running on your system:

```bash
# Windows
net start MongoDB

# macOS/Linux
sudo systemctl start mongod
```

### 5. Run the Server

```bash
npm start
```

## API Endpoints

### POST /contact
Submit a new contact form
```json
{
  "FirstName": "John",
  "LastName": "Doe",
  "Email": "john@example.com",
  "Message": "Hello, this is a test message!"
}
```

### GET /contact
Get all contact submissions (latest first)

### GET /contact/:id
Get a specific contact by ID

### DELETE /contact/:id
Delete a contact by ID

### GET /health
Health check endpoint

## Email Notification

When a form is submitted:
1. ✅ Data is saved to MongoDB
2. 📧 Beautiful HTML email is sent to your Gmail
3. 🎉 Success response is returned to frontend

## Email Template Features

- 🎨 Modern HTML design with gradients
- 📱 Mobile-responsive layout
- 🕒 Timestamp of submission
- 👤 Complete contact information
- 💬 Full message content

## Database Schema

```javascript
{
  FirstName: String (required),
  LastName: String (required),
  Email: String (required),
  Message: String (required),
  createdAt: Date (auto-generated)
}
```

## Security Features

- 🔒 Environment variables for sensitive data
- ✅ Input validation
- 🛡️ Error handling
- 📧 Secure Gmail SMTP

## Testing

Test the contact form by:
1. Starting the server
2. Submitting the contact form on your portfolio
3. Checking your Gmail for notifications
4. Verifying data in MongoDB

## Troubleshooting

### Email not sending?
- Check Gmail App Password is correct
- Verify 2FA is enabled on Gmail
- Check console for error messages

### Database connection issues?
- Ensure MongoDB is running
- Check connection string in `.env`
- Verify database permissions

### CORS issues?
- Server includes CORS middleware
- Frontend should connect to `http://localhost:5050`
