// script.js

let gameId = null;
let currentRow = 0;

// ---------------- LOGIN ----------------
function login() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  fetch("http://localhost:4567/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
    credentials: "include" // <--- enviamos cookie HttpOnly
  })
    .then(res => res.json())
    .then(data => {
      if (data.message === "login successful") {
        // Redirigimos al dashboard / juego
        document.getElementById("auth").classList.add("hidden");
        document.getElementById("game").classList.remove("hidden");
      } else {
        alert("Login incorrecto");
      }
    })
    .catch(err => console.error("Error login:", err));
}

// ---------------- START GAME ----------------
function startGame() {
  fetch("http://localhost:4567/games", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({}),
    credentials: "include"
  })
    .then(res => res.json())
    .then(data => {
      if (!data.id) {
        alert(data.error || "No se pudo iniciar el juego");
        return;
      }
      gameId = data.id;
      createBoard(data.word_length || 5);
      document.getElementById("message").innerText = "Juego iniciado!";
    })
    .catch(err => console.error("Error startGame:", err));
}

// ---------------- CREATE BOARD ----------------
function createBoard(length) {
  const board = document.getElementById("board");
  board.innerHTML = "";
  currentRow = 0;

  for (let i = 0; i < 6; i++) {
    const row = document.createElement("div");
    row.classList.add("row");

    for (let j = 0; j < length; j++) {
      const cell = document.createElement("div");
      cell.classList.add("cell");
      row.appendChild(cell);
    }

    board.appendChild(row);
  }
}

// ---------------- SEND GUESS ----------------
function sendGuess() {
  const guess = document.getElementById("guessInput").value.trim().toLowerCase();
  if (!guess) return;

  fetch(`http://localhost:4567/games/${gameId}/attempts`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ guess }),
    credentials: "include"
  })
    .then(res => res.json())
    .then(data => {
      if (data.error) {
        alert(data.error);
        return;
      }

      updateBoard(guess, data.feedback.positions.map((pos, i) => {
        if (pos) return "green";
        else if (data.feedback.letter_matches_count > 0 && data.feedback.letter_matches_count >= 1) return "yellow";
        else return "gray";
      }));

      if (data.status === "won") {
        document.getElementById("message").innerText = "Ganaste 🎉";
      } else if (data.status === "lost") {
        document.getElementById("message").innerText = "Perdiste 😢";
      }

      currentRow++;
      document.getElementById("guessInput").value = "";
    })
    .catch(err => console.error("Error sendGuess:", err));
}

// ---------------- UPDATE BOARD ----------------
function updateBoard(word, feedback) {
  const rows = document.querySelectorAll(".row");
  if (currentRow >= rows.length) return;

  const cells = rows[currentRow].children;
  for (let i = 0; i < cells.length; i++) {
    cells[i].innerText = word[i] || "";
    cells[i].className = "cell"; // reset clases
    if (feedback[i]) cells[i].classList.add(feedback[i]);
  }
}

// ---------------- LOGOUT ----------------
function logout() {
  fetch("http://localhost:4567/logout", {
    method: "POST",
    credentials: "include"
  }).finally(() => {
    document.getElementById("auth").classList.remove("hidden");
    document.getElementById("game").classList.add("hidden");
    gameId = null;
    currentRow = 0;
    document.getElementById("board").innerHTML = "";
    document.getElementById("message").innerText = "";
  });
}