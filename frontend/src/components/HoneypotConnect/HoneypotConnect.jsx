import React, { useState } from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Card,
  CardContent,
  Grid,
  Alert,
  CircularProgress,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
} from '@mui/material';
import {
  PlayArrow,
  Stop,
  CheckCircle,
  Error,
  Refresh,
} from '@mui/icons-material';
import { api } from '../../services/api';
import toast from 'react-hot-toast';

const HoneypotConnect = () => {
  const [formData, setFormData] = useState({
    name: '',
    honeypot_type: 't-pot',
    api_url: '',
    api_key: '',
    username: '',
    password: '',
  });

  const [connections, setConnections] = useState([]);
  const [loading, setLoading] = useState(false);
  const [testing, setTesting] = useState(false);

  const honeypotTypes = [
    { value: 't-pot', label: 'T-Pot' },
    { value: 'cowrie', label: 'Cowrie' },
    { value: 'dionaea', label: 'Dionaea' },
    { value: 'glutton', label: 'Glutton' },
    { value: 'custom', label: 'Custom' },
  ];

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });
  };

  const handleTestConnection = async () => {
    setTesting(true);
    try {
      // Here you would call your backend to test the connection
      const response = await api.post('/connect', formData);
      toast.success('Connection successful!');
      return true;
    } catch (error) {
      toast.error('Connection failed: ' + error.message);
      return false;
    } finally {
      setTesting(false);
    }
  };

  const handleConnect = async () => {
    if (!formData.name || !formData.api_url) {
      toast.error('Please fill in all required fields');
      return;
    }

    setLoading(true);
    try {
      const response = await api.post('/connect', formData);

      // Add to connections list
      const newConnection = {
        id: response.data.data.connection_id,
        ...formData,
        status: 'connected',
        lastFetch: new Date().toISOString(),
      };

      setConnections([...connections, newConnection]);
      toast.success(`Successfully connected to ${formData.name}`);

      // Reset form
      setFormData({
        name: '',
        honeypot_type: 't-pot',
        api_url: '',
        api_key: '',
        username: '',
        password: '',
      });
    } catch (error) {
      toast.error('Connection error: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDisconnect = (connectionId) => {
    setConnections(connections.map(conn =>
      conn.id === connectionId
        ? { ...conn, status: 'disconnected' }
        : conn
    ));
    toast.success('Connection disconnected');
  };

  const handleRefresh = (connectionId) => {
    const connection = connections.find(c => c.id === connectionId);
    if (connection) {
      toast.success(`Refreshing ${connection.name}...`);
      // Here you would call your backend to refresh the connection
    }
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'connected': return 'success';
      case 'disconnected': return 'default';
      case 'error': return 'error';
      case 'fetching': return 'warning';
      default: return 'default';
    }
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Grid container spacing={3}>
        {/* Connection Form */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h5" gutterBottom>
              Connect to Honeypot
            </Typography>
            <Typography variant="body2" color="textSecondary" paragraph>
              Connect to a live honeypot to fetch logs in real-time
            </Typography>

            <Box component="form" sx={{ mt: 2 }}>
              <TextField
                fullWidth
                label="Connection Name"
                name="name"
                value={formData.name}
                onChange={handleChange}
                required
                sx={{ mb: 2 }}
              />

              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Honeypot Type</InputLabel>
                <Select
                  name="honeypot_type"
                  value={formData.honeypot_type}
                  label="Honeypot Type"
                  onChange={handleChange}
                >
                  {honeypotTypes.map((type) => (
                    <MenuItem key={type.value} value={type.value}>
                      {type.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <TextField
                fullWidth
                label="API URL"
                name="api_url"
                value={formData.api_url}
                onChange={handleChange}
                required
                placeholder="http://your-honeypot-ip:port/api"
                sx={{ mb: 2 }}
              />

              <TextField
                fullWidth
                label="API Key (Optional)"
                name="api_key"
                value={formData.api_key}
                onChange={handleChange}
                type="password"
                sx={{ mb: 2 }}
              />

              <Grid container spacing={2} sx={{ mb: 2 }}>
                <Grid item xs={6}>
                  <TextField
                    fullWidth
                    label="Username (Optional)"
                    name="username"
                    value={formData.username}
                    onChange={handleChange}
                  />
                </Grid>
                <Grid item xs={6}>
                  <TextField
                    fullWidth
                    label="Password (Optional)"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    type="password"
                  />
                </Grid>
              </Grid>

              <Box sx={{ display: 'flex', gap: 2, mt: 3 }}>
                <Button
                  variant="outlined"
                  onClick={handleTestConnection}
                  disabled={testing || !formData.api_url}
                  startIcon={testing ? <CircularProgress size={20} /> : <Refresh />}
                >
                  {testing ? 'Testing...' : 'Test Connection'}
                </Button>

                <Button
                  variant="contained"
                  onClick={handleConnect}
                  disabled={loading || !formData.name || !formData.api_url}
                  startIcon={loading ? <CircularProgress size={20} /> : <PlayArrow />}
                  sx={{ flexGrow: 1 }}
                >
                  {loading ? 'Connecting...' : 'Connect'}
                </Button>
              </Box>
            </Box>

            <Alert severity="info" sx={{ mt: 3 }}>
              <Typography variant="body2">
                <strong>Note:</strong> For T-Pot, the API URL is typically: http://your-tpot-ip:64297/api
              </Typography>
            </Alert>
          </Paper>
        </Grid>

        {/* Active Connections */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h5">
                Active Connections
              </Typography>
              <Typography variant="body2" color="textSecondary">
                {connections.filter(c => c.status === 'connected').length} connected
              </Typography>
            </Box>

            {connections.length === 0 ? (
              <Alert severity="info">
                No active connections. Connect to a honeypot to see it here.
              </Alert>
            ) : (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {connections.map((connection) => (
                      <TableRow key={connection.id}>
                        <TableCell>
                          <Typography variant="body2">
                            {connection.name}
                          </Typography>
                          <Typography variant="caption" color="textSecondary">
                            {connection.api_url}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={connection.honeypot_type}
                            size="small"
                            variant="outlined"
                          />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={connection.status}
                            size="small"
                            color={getStatusColor(connection.status)}
                          />
                        </TableCell>
                        <TableCell align="right">
                          <IconButton
                            size="small"
                            onClick={() => handleRefresh(connection.id)}
                            color="primary"
                          >
                            <Refresh fontSize="small" />
                          </IconButton>
                          <IconButton
                            size="small"
                            onClick={() => handleDisconnect(connection.id)}
                            color="error"
                          >
                            <Stop fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}

            {/* Connection Stats */}
            {connections.length > 0 && (
              <Box sx={{ mt: 3, p: 2, backgroundColor: 'background.paper', borderRadius: 1 }}>
                <Typography variant="subtitle2" gutterBottom>
                  Connection Statistics
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={4}>
                    <Typography variant="caption" color="textSecondary">
                      Total
                    </Typography>
                    <Typography variant="h6">
                      {connections.length}
                    </Typography>
                  </Grid>
                  <Grid item xs={4}>
                    <Typography variant="caption" color="textSecondary">
                      Active
                    </Typography>
                    <Typography variant="h6" color="success.main">
                      {connections.filter(c => c.status === 'connected').length}
                    </Typography>
                  </Grid>
                  <Grid item xs={4}>
                    <Typography variant="caption" color="textSecondary">
                      Logs Fetched
                    </Typography>
                    <Typography variant="h6">
                      0
                    </Typography>
                  </Grid>
                </Grid>
              </Box>
            )}
          </Paper>
        </Grid>

        {/* Connection Guide */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Connection Guide
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>
                      T-Pot Setup
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      1. Ensure T-Pot is running<br />
                      2. Enable API access<br />
                      3. Use port 64297 for web interface<br />
                      4. API URL: http://[tpot-ip]:64297/api
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={4}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>
                      Cowrie Setup
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      1. Enable JSON logging<br />
                      2. Configure web API<br />
                      3. Use default port 2222<br />
                      4. API URL: http://[cowrie-ip]:2222/api
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={4}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="subtitle1" gutterBottom>
                      Custom Honeypot
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      1. Ensure JSON API endpoint<br />
                      2. Provide authentication if needed<br />
                      3. Test connection first<br />
                      4. Monitor logs in dashboard
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Paper>
        </Grid>
      </Grid>
    </Container>
  );
};

export default HoneypotConnect;