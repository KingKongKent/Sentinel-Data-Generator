/* ========================================================================
   Brute Force Demo — Client logic
   ======================================================================== */

(() => {
    "use strict";

    // ---- Config ----------------------------------------------------------
    // When running locally with SWA CLI the API is proxied at /api.
    // In production (Azure SWA linked backend) the same /api prefix works.
    const API_URL = "/api/attempt";

    // ---- DOM refs --------------------------------------------------------
    const nicknamePanel  = document.getElementById("nickname-panel");
    const nicknameInput  = document.getElementById("nickname-input");
    const nicknameBtn    = document.getElementById("nickname-btn");
    const pinPanel       = document.getElementById("pin-panel");
    const playerName     = document.getElementById("player-name");
    const changeName     = document.getElementById("change-name");
    const pinDisplay     = document.getElementById("pin-display");
    const dots           = pinDisplay.querySelectorAll(".dot");
    const resultFeedback = document.getElementById("result-feedback");
    const attemptCount   = document.getElementById("attempt-count");

    // ---- State -----------------------------------------------------------
    let nickname  = "";
    let pin       = "";
    let attempts  = 0;
    let sending   = false;

    // ---- Nickname flow ---------------------------------------------------
    nicknameInput.addEventListener("input", () => {
        nicknameBtn.disabled = nicknameInput.value.trim().length === 0;
    });

    nicknameInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && nicknameInput.value.trim()) startGame();
    });

    nicknameBtn.addEventListener("click", startGame);

    changeName.addEventListener("click", () => {
        pinPanel.classList.add("hidden");
        nicknamePanel.classList.remove("hidden");
        nicknameInput.focus();
        resetPin();
    });

    function startGame() {
        nickname = nicknameInput.value.trim();
        if (!nickname) return;
        playerName.textContent = nickname;
        nicknamePanel.classList.add("hidden");
        pinPanel.classList.remove("hidden");
        resetPin();
    }

    // ---- PIN pad ---------------------------------------------------------
    document.querySelector(".numpad").addEventListener("click", (e) => {
        const btn = e.target.closest(".num");
        if (!btn || sending) return;

        const digit = btn.dataset.digit;

        if (digit === "clear") {
            pin = pin.slice(0, -1);
            updateDots();
            return;
        }

        if (digit === "submit") {
            if (pin.length === 4) submitAttempt();
            return;
        }

        if (pin.length < 4) {
            pin += digit;
            updateDots();
            // Auto-submit when 4 digits entered
            if (pin.length === 4) submitAttempt();
        }
    });

    // Keyboard support
    document.addEventListener("keydown", (e) => {
        if (pinPanel.classList.contains("hidden") || sending) return;

        if (e.key >= "0" && e.key <= "9" && pin.length < 4) {
            pin += e.key;
            updateDots();
            if (pin.length === 4) submitAttempt();
        } else if (e.key === "Backspace") {
            pin = pin.slice(0, -1);
            updateDots();
        } else if (e.key === "Enter" && pin.length === 4) {
            submitAttempt();
        }
    });

    function updateDots() {
        dots.forEach((dot, i) => {
            dot.textContent = pin[i] || "";
            dot.classList.toggle("filled", i < pin.length);
        });
    }

    function resetPin() {
        pin = "";
        updateDots();
        resultFeedback.classList.add("hidden");
    }

    // ---- API call --------------------------------------------------------
    async function submitAttempt() {
        if (sending) return;
        sending = true;

        try {
            const res = await fetch(API_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ nickname, pincode: pin }),
            });

            const data = await res.json();

            attempts++;
            attemptCount.textContent = attempts;

            showResult(data.result === "Success");
        } catch (err) {
            console.error("API error:", err);
            resultFeedback.textContent = "⚠ Connection error — try again";
            resultFeedback.className = "failure";
            resultFeedback.classList.remove("hidden");
        } finally {
            sending = false;
            // Reset PIN after a short delay so the user sees the result
            setTimeout(resetPin, 1200);
        }
    }

    function showResult(success) {
        if (success) {
            resultFeedback.textContent = "🎉 PIN CRACKED!";
            resultFeedback.className = "success";
        } else {
            resultFeedback.textContent = "❌ Wrong PIN — try again";
            resultFeedback.className = "failure";
            pinDisplay.classList.add("shake");
            setTimeout(() => pinDisplay.classList.remove("shake"), 400);
        }
        resultFeedback.classList.remove("hidden");
    }
})();
