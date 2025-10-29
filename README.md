1. Install Dependencies
npm install

2. Create .env File

Add the following in your backend root:

PORT=5000
DATABASE_URL & JWT_SECRET(from env)

3. Run the Server
npm start


Server runs on http://localhost:5000

🧾 API Endpoints
Method	Endpoint	Description
POST	/api/auth/signup	Register new user
POST	/api/auth/login	Login user & issue JWT
GET	/api/events	Fetch user’s events
POST	/api/events	Create event
PATCH	/api/events/:id	Update event (e.g., make swappable)
GET	/api/swappable-slots	Fetch swappable slots from other users
POST	/api/swap-request	Request slot swap
GET	/api/requests/incoming	Fetch incoming requests
GET	/api/requests/outgoing	Fetch outgoing requests
POST	/api/swap-response/:id	Accept or reject swap
🧠 Swap Logic Overview

A user marks a slot as SWAPPABLE.

Another user can request to swap it for one of their own swappable slots.

The system verifies both slots and creates a SwapRequest.

The recipient can Accept or Reject the request.

If accepted, slot ownership is swapped and both marked BUSY again.
