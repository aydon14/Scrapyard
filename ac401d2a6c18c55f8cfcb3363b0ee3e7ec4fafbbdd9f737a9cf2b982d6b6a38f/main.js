const { app, BrowserWindow, Menu, ipcMain } = require('electron');

function createWindow() {
  const win = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      //devTools: false,
      nodeIntegration: true,
      contextIsolation: false
    }
  });
  
  //Menu.setApplicationMenu(null);

  win.loadFile('index.html');
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  createWindow();
});

ipcMain.on('main-console', (event, message) => {
  console.log(message);
});