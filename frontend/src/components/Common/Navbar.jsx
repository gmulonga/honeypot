import React from 'react';
import {
  AppBar,
  Toolbar,
  Typography,
  Box,
  IconButton,
  Tooltip,
} from '@mui/material';
import {
  Security,
  Notifications,
  Settings,
  AccountCircle,
} from '@mui/icons-material';

const Navbar = () => {
  return (
    <AppBar position="static" elevation={0}>
      <Toolbar>
        <Box sx={{ display: 'flex', alignItems: 'center', flexGrow: 1 }}>
          <Security sx={{ mr: 2 }} />
          <Typography variant="h6" component="div">
            Honeypot Analyzer
          </Typography>
          <Typography variant="caption" sx={{ ml: 2, opacity: 0.7 }}>
            Kenyan Cloud Security Research
          </Typography>
        </Box>

        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Notifications">
            <IconButton color="inherit">
              <Notifications />
            </IconButton>
          </Tooltip>
          <Tooltip title="Settings">
            <IconButton color="inherit">
              <Settings />
            </IconButton>
          </Tooltip>
          <Tooltip title="Account">
            <IconButton color="inherit">
              <AccountCircle />
            </IconButton>
          </Tooltip>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Navbar;