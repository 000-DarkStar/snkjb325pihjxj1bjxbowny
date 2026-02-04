const express = require("express");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*", // autorise Cloudflare Pages
    methods: ["GET", "POST"]
  }
});

let onlineUsers = 0;

io.on("connection", (socket) => {
  onlineUsers++;
  io.emit("updateUsers", onlineUsers);

  socket.on("disconnect", () => {
    onlineUsers--;
    if (onlineUsers < 0) onlineUsers = 0;
    io.emit("updateUsers", onlineUsers);
  });
});

app.get("/", (req, res) => {
  res.send("Backend online ✔️");
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
