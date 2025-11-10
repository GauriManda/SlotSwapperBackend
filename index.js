const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(cors());
app.use(express.json());

// PostgreSQL connection
const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// Auth Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

// ==================== AUTH ROUTES ====================

// Sign Up
app.post("/api/auth/signup", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Check if user exists
    const userExists = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: "Email already registered" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const result = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email",
      [name, email, hashedPassword]
    );

    const user = result.rows[0];

    // Generate JWT
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.status(201).json({ user, token });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({ error: "Server error during signup" });
  }
});

// Log In
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find user
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];

    // Check password
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate JWT
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      user: { id: user.id, name: user.name, email: user.email },
      token,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Server error during login" });
  }
});

// Get user's events
app.get("/api/events", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM events WHERE user_id = $1 ORDER BY start_time ASC",
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Get events error:", error);
    res.status(500).json({ error: "Failed to fetch events" });
  }
});

// Create event
app.post("/api/events", authenticateToken, async (req, res) => {
  const { title, startTime, endTime, status } = req.body;

  try {
    // Validate status
    if (!["BUSY", "SWAPPABLE"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    // Validate time
    if (new Date(startTime) >= new Date(endTime)) {
      return res
        .status(400)
        .json({ error: "Start time must be before end time" });
    }

    const result = await pool.query(
      "INSERT INTO events (user_id, title, start_time, end_time, status) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [req.user.id, title, startTime, endTime, status]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Create event error:", error);
    res.status(500).json({ error: "Failed to create event" });
  }
});

// Update event
app.put("/api/events/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, startTime, endTime, status } = req.body;

  try {
    // Check ownership
    const event = await pool.query(
      "SELECT * FROM events WHERE id = $1 AND user_id = $2",
      [id, req.user.id]
    );

    if (event.rows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }

    // Validate status
    if (status && !["BUSY", "SWAPPABLE", "SWAP_PENDING"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    // Build update query
    const updates = [];
    const values = [];
    let paramCount = 1;

    if (title) {
      updates.push(`title = $${paramCount++}`);
      values.push(title);
    }
    if (startTime) {
      updates.push(`start_time = $${paramCount++}`);
      values.push(startTime);
    }
    if (endTime) {
      updates.push(`end_time = $${paramCount++}`);
      values.push(endTime);
    }
    if (status) {
      updates.push(`status = $${paramCount++}`);
      values.push(status);
    }

    values.push(id, req.user.id);

    const result = await pool.query(
      `UPDATE events SET ${updates.join(
        ", "
      )}, updated_at = NOW() WHERE id = $${paramCount} AND user_id = $${
        paramCount + 1
      } RETURNING *`,
      values
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Update event error:", error);
    res.status(500).json({ error: "Failed to update event" });
  }
});

// Delete event
app.delete("/api/events/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Check if event has pending swap requests
    const pendingSwaps = await pool.query(
      "SELECT * FROM swap_requests WHERE (requester_slot_id = $1 OR recipient_slot_id = $1) AND status = $2",
      [id, "PENDING"]
    );

    if (pendingSwaps.rows.length > 0) {
      return res
        .status(400)
        .json({ error: "Cannot delete event with pending swap requests" });
    }

    const result = await pool.query(
      "DELETE FROM events WHERE id = $1 AND user_id = $2 RETURNING *",
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }

    res.json({ message: "Event deleted successfully" });
  } catch (error) {
    console.error("Delete event error:", error);
    res.status(500).json({ error: "Failed to delete event" });
  }
});

// Get swappable slots (excluding user's own)
app.get("/api/swappable-slots", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT e.*, u.name as user_name, u.email as user_email 
       FROM events e 
       JOIN users u ON e.user_id = u.id 
       WHERE e.status = $1 AND e.user_id != $2 
       ORDER BY e.start_time ASC`,
      ["SWAPPABLE", req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Get swappable slots error:", error);
    res.status(500).json({ error: "Failed to fetch swappable slots" });
  }
});

// Create swap request
app.post("/api/swap-request", authenticateToken, async (req, res) => {
  const { mySlotId, theirSlotId } = req.body;

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Validate my slot
    const mySlot = await client.query(
      "SELECT * FROM events WHERE id = $1 AND user_id = $2",
      [mySlotId, req.user.id]
    );

    if (mySlot.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Your slot not found" });
    }

    if (mySlot.rows[0].status !== "SWAPPABLE") {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Your slot must be swappable" });
    }

    // Validate their slot
    const theirSlot = await client.query(
      "SELECT * FROM events WHERE id = $1 AND user_id != $2",
      [theirSlotId, req.user.id]
    );

    if (theirSlot.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Their slot not found" });
    }

    if (theirSlot.rows[0].status !== "SWAPPABLE") {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Their slot must be swappable" });
    }

    // Check for existing pending request
    const existingRequest = await client.query(
      "SELECT * FROM swap_requests WHERE (requester_slot_id = $1 OR recipient_slot_id = $1 OR requester_slot_id = $2 OR recipient_slot_id = $2) AND status = $3",
      [mySlotId, theirSlotId, "PENDING"]
    );

    if (existingRequest.rows.length > 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        error: "One or both slots already have pending swap requests",
      });
    }

    // Create swap request
    const swapRequest = await client.query(
      "INSERT INTO swap_requests (requester_id, recipient_id, requester_slot_id, recipient_slot_id, status) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [req.user.id, theirSlot.rows[0].user_id, mySlotId, theirSlotId, "PENDING"]
    );

    // Update both slots to SWAP_PENDING
    await client.query("UPDATE events SET status = $1 WHERE id = $2", [
      "SWAP_PENDING",
      mySlotId,
    ]);
    await client.query("UPDATE events SET status = $1 WHERE id = $2", [
      "SWAP_PENDING",
      theirSlotId,
    ]);

    await client.query("COMMIT");

    res.status(201).json(swapRequest.rows[0]);
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Create swap request error:", error);
    res.status(500).json({ error: "Failed to create swap request" });
  } finally {
    client.release();
  }
});

// Respond to swap request
app.post(
  "/api/swap-response/:requestId",
  authenticateToken,
  async (req, res) => {
    const { requestId } = req.params;
    const { accept } = req.body;

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // Get swap request
      const swapRequest = await client.query(
        "SELECT * FROM swap_requests WHERE id = $1 AND recipient_id = $2 AND status = $3",
        [requestId, req.user.id, "PENDING"]
      );

      if (swapRequest.rows.length === 0) {
        await client.query("ROLLBACK");
        return res
          .status(404)
          .json({ error: "Swap request not found or already processed" });
      }

      const request = swapRequest.rows[0];

      if (accept) {
        // Get both slots
        const slots = await client.query(
          "SELECT * FROM events WHERE id IN ($1, $2)",
          [request.requester_slot_id, request.recipient_slot_id]
        );

        if (slots.rows.length !== 2) {
          await client.query("ROLLBACK");
          return res.status(400).json({ error: "One or both slots not found" });
        }

        const requesterSlot = slots.rows.find(
          (s) => s.id === request.requester_slot_id
        );
        const recipientSlot = slots.rows.find(
          (s) => s.id === request.recipient_slot_id
        );

        // Swap ownership
        await client.query(
          "UPDATE events SET user_id = $1, status = $2 WHERE id = $3",
          [recipientSlot.user_id, "BUSY", requesterSlot.id]
        );

        await client.query(
          "UPDATE events SET user_id = $1, status = $2 WHERE id = $3",
          [requesterSlot.user_id, "BUSY", recipientSlot.id]
        );

        // Update swap request status
        await client.query(
          "UPDATE swap_requests SET status = $1, responded_at = NOW() WHERE id = $2",
          ["ACCEPTED", requestId]
        );
      } else {
        // Revert both slots to SWAPPABLE
        await client.query(
          "UPDATE events SET status = $1 WHERE id IN ($2, $3)",
          ["SWAPPABLE", request.requester_slot_id, request.recipient_slot_id]
        );

        // Update swap request status
        await client.query(
          "UPDATE swap_requests SET status = $1, responded_at = NOW() WHERE id = $2",
          ["REJECTED", requestId]
        );
      }

      await client.query("COMMIT");

      const updatedRequest = await pool.query(
        "SELECT * FROM swap_requests WHERE id = $1",
        [requestId]
      );

      res.json(updatedRequest.rows[0]);
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("Swap response error:", error);
      res.status(500).json({ error: "Failed to process swap response" });
    } finally {
      client.release();
    }
  }
);

// Get incoming swap requests
app.get("/api/swap-requests/incoming", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT sr.*, 
              u.name as requester_name, 
              u.email as requester_email,
              e1.title as requester_slot_title, 
              e1.start_time as requester_slot_start, 
              e1.end_time as requester_slot_end,
              e2.title as recipient_slot_title, 
              e2.start_time as recipient_slot_start, 
              e2.end_time as recipient_slot_end
       FROM swap_requests sr
       JOIN users u ON sr.requester_id = u.id
       JOIN events e1 ON sr.requester_slot_id = e1.id
       JOIN events e2 ON sr.recipient_slot_id = e2.id
       WHERE sr.recipient_id = $1 AND sr.status = $2
       ORDER BY sr.created_at DESC`,
      [req.user.id, "PENDING"]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Get incoming requests error:", error);
    res.status(500).json({ error: "Failed to fetch incoming requests" });
  }
});

// Get outgoing swap requests
app.get("/api/swap-requests/outgoing", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT sr.*, 
              u.name as recipient_name, 
              u.email as recipient_email,
              e1.title as requester_slot_title, 
              e1.start_time as requester_slot_start, 
              e1.end_time as requester_slot_end,
              e2.title as recipient_slot_title, 
              e2.start_time as recipient_slot_start, 
              e2.end_time as recipient_slot_end
       FROM swap_requests sr
       JOIN users u ON sr.recipient_id = u.id
       JOIN events e1 ON sr.requester_slot_id = e1.id
       JOIN events e2 ON sr.recipient_slot_id = e2.id
       WHERE sr.requester_id = $1
       ORDER BY sr.created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Get outgoing requests error:", error);
    res.status(500).json({ error: "Failed to fetch outgoing requests" });
  }
});

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});
app.get("/", (req, res) => {
  res.send("SlotSwapper Backend is running ");
});

app.get("/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({
      message: "✅ Connected to PostgreSQL successfully!",
      server_time: result.rows[0].now,
    });
  } catch (error) {
    console.error("Database connection test failed:", error);
    res.status(500).json({ error: "❌ Failed to connect to the database" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
