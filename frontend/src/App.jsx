import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { Toaster } from 'react-hot-toast';

import Dashboard from './components/dashboard/dashboard';
import LogUpload from './components/LogUpload/LogUpload';
import HoneypotConnect from './components/HoneypotConnect/HoneypotConnect';
import AnalysisDashboard from './components/Analysis/AnalysisDashboard';
import Navbar from './components/Common/Navbar';
import Sidebar from './components/Common/Sidebar';

const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
    background: {
      default: '#0a1929',
      paper: '#132f4c',
    },
  }

});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <div style={{ display: 'flex' }}>
          <Sidebar />
          <div style={{ flexGrow: 1 }}>
            <Navbar />
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/upload" element={<LogUpload />} />
              <Route path="/connect" element={<HoneypotConnect />} />
              <Route path="/analysis" element={<AnalysisDashboard />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </div>
      </Router>
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#132f4c',
            color: '#fff',
          },
        }}
      />
    </ThemeProvider>
  );
}

export default App;