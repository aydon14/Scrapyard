// Modules
const { app, BrowserWindow, ipcMain } = require('electron');
const globals = require('./globals.js');
Object.assign(global, globals);

// Local Variables
var fullExit = false;
var fullscreen = false;

function createWindow(destination, id=0) {
    if (id==0) { // console
        windows.push(new BrowserWindow({
            width: 1600,
            height: 900,
            titleBarStyle: 'hidden',
            webPreferences: {
                // devTools: false,
                nodeIntegration: true,
                contextIsolation: false
            }
        }));
    
        windows[0].loadFile('src/html/' + destination + '.html');

        windows[0].on('close', (event) => {
            if (!fullExit) {
                event.preventDefault();
            }
            
            console.log('You can\'t disable the console only! Use the exit button.');
        });
    } else if (id==1) { // Logger
        
    }
}

app.whenReady().then(() => {
    createWindow('console', 0);
});

ipcMain.on('console', (_, arg) => {
    if (arg == 'darkmode') { // Universal
        for (var i = 0; i < windows.length; i++) {
            windows[i].webContents.send('toggle-darkmode');
        }
    } else if (arg == 'quit-app') {
        fullExit = true
        app.quit();
    } else if (arg.substring(0, 9) == "zoomLevel") {
        zoomLevel = Number(arg.substring(10)) / 100;
        windows[0].webContents.setZoomLevel(zoomLevel);
    } else if (arg == 'fullscreen') {
        if (fullscreen == false) {
            fullscreen = true;
            windows[0].setFullScreen(true);
        } else {
            fullscreen = false;
            windows[0].setFullScreen(false);
        }
    }
});