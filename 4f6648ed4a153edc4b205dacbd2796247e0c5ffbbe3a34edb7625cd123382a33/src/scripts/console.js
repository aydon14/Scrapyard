// Elements
bodyElement = document.getElementById('body');
footerElement = document.getElementById('footer');
board1Element = document.getElementById('board1');
board2Element = document.getElementById('board2');
board3Element = document.getElementById('board3');
board4Element = document.getElementById('board4');
board5Element = document.getElementById('board5');
board6Element = document.getElementById('board6');
board7Element = document.getElementById('board7');
resourceElement = document.getElementById('switch1');
darkModeElement = document.getElementById('switch2');
fullscreenElement = document.getElementById('switch3');
exitButtonElement = document.getElementById('exitButton');
saveButtonElement = document.getElementById('saveButton');
aboutButtonElement = document.getElementById('aboutButton');
loggerButtonElement = document.getElementById('loggerButton');
zoomTextElement = document.getElementById('zoom');
dragBoxElement = document.getElementById('dragbox');

// All Switches
document.querySelectorAll('.pref-switch').forEach(switchElement => {
    switchElement.addEventListener('click', function() {
        this.classList.toggle('green');
    });
});

// Local Variables
var darkmodeFlag = false

// ipcRenderer
const { ipcRenderer } = require('electron');

darkModeElement.addEventListener('click', () => {
    ipcRenderer.send('console', 'darkmode');
    if (darkmodeFlag == false) {
        bodyElement.style.backgroundColor='black';
        bodyElement.style.color='white';
        exitButtonElement.style.backgroundColor='rgba(255, 100, 100, 0.8)';
        saveButtonElement.style.backgroundColor='rgba(50, 150, 255, 0.8)';
        aboutButtonElement.style.backgroundColor='rgba(100, 255, 100, 0.8)';
        loggerButtonElement.style.backgroundColor='rgba(255, 255, 100, 0.8)';
        zoomTextElement.style.borderColor='rgb(225, 225, 225)';
        zoomTextElement.style.backgroundColor='rgb(150, 150, 150)';
        dragBoxElement.style.backgroundColor='rgba(255, 100, 100, 0.8)';
        dragBoxElement.style.color='rgba(255, 0, 0, 0.8)';
        footerElement.style.backgroundColor='rgb(50, 50, 50)';
        darkmodeFlag = true;
    } else {
        bodyElement.style.backgroundColor='rgb(225, 225, 225)';
        bodyElement.style.color='black';
        exitButtonElement.style.backgroundColor='rgba(255, 0, 0, 0.5);';
        saveButtonElement.style.backgroundColor='rgba(0, 100, 255, 0.5)';
        aboutButtonElement.style.backgroundColor='rgba(0, 255, 0, 0.5)';
        loggerButtonElement.style.backgroundColor='rgba(255, 255, 0, 0.5)';
        zoomTextElement.style.borderColor='#333';
        zoomTextElement.style.backgroundColor='rgb(200, 200, 200)';
        dragBoxElement.style.backgroundColor='rgba(255, 100, 100, 0.8)';
        dragBoxElement.style.color='rgba(255, 0, 0, 0.5)';
        footerElement.style.backgroundColor='rgb(220, 220, 220)';
        darkmodeFlag = false;
    }
});

fullscreenElement.addEventListener('click', () => {
    ipcRenderer.send('console', 'fullscreen');
});

exitButtonElement.addEventListener('click', () => {
    ipcRenderer.send('console', 'quit-app');
});

zoomTextElement.addEventListener('keydown', function(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        var zoomLevel = Number(event.target.value);
        if (Number.isInteger(zoomLevel) && zoomLevel <= 500 && zoomLevel >= -500) {
            ipcRenderer.send('console', ('zoomLevel ' + zoomLevel));
        } else {
            // Show the error in the logger.
        }
    }
});

/*
function buttonUpdate() {
    let boards = [board1Element, board2Element, board3Element, board4Element, board5Element, board6Element, board7Element];
    boards.forEach((board, index) => {
        if (boardFlag == index + 1) {
            board.style.display = "block";
        } else {
            board.style.display = "none";
        }
    });
} */