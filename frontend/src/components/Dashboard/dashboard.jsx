import React, { useState, useEffect } from 'react';
import {
  Grid,
  Paper,
  Typography,
  Container,
  Box,
  Alert,
  CircularProgress,
  Button,
} from '@mui/material';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { api, getDashboardStats } from '../../services/api';
import StatsCards from './StatsCards';

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [chartData, setChartData] = useState({
    timeline: [],
    attackTypes: [],
  });

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const response = await getDashboardStats();
      setStats(response);

      // Process data for charts
      if (response) {
        const timeline = processTimelineData(response);
        const attackTypes = processAttackTypes(response);
        setChartData({ timeline, attackTypes });
      }

      setError(null);
    } catch (error) {
      console.error('Error fetching dashboard data:', error);
      setError('Failed to load dashboard data. Please check if the backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const processTimelineData = (data) => {
    // Create mock timeline data for demo
    // Replace this with actual timeline data from your API
    return Array.from({ length: 24 }, (_, i) => ({
      hour: `${i}:00`,
      attacks: Math.floor(Math.random() * 100) + 50,
    }));
  };

  const processAttackTypes = (data) => {
    if (!data.attack_distribution) {
      return [];
    }

    const colors = ['#8884d8', '#82ca9d', '#ffc658', '#ff8042', '#0088fe', '#00C49F', '#FFBB28', '#FF8042'];

    return Object.entries(data.attack_distribution).map(([name, value], index) => ({
      name: name.replace('_', ' ').toUpperCase(),
      value,
      color: colors[index % colors.length],
    }));
  };

  const handleManualRefresh = () => {
    fetchDashboardData();
  };

  if (loading && !stats) {
    return (
      <Container sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <Box sx={{ textAlign: 'center' }}>
          <CircularProgress />
          <Typography sx={{ mt: 2 }}>Loading dashboard data...</Typography>
        </Box>
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      {error && (
        <Alert
          severity="error"
          sx={{ mb: 3 }}
          action={
            <Button color="inherit" size="small" onClick={fetchDashboardData}>
              Retry
            </Button>
          }
        >
          {error}
        </Alert>
      )}

      <StatsCards stats={stats} />

      <Grid container spacing={3} sx={{ mt: 2 }}>
        {/* Attack Timeline */}
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 2, height: '100%' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6" gutterBottom>
                Attack Timeline (Last 24 Hours)
              </Typography>
              <Button size="small" onClick={handleManualRefresh}>
                Refresh
              </Button>
            </Box>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={chartData.timeline}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="hour" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="attacks"
                  stroke="#1976d2"
                  strokeWidth={2}
                  dot={{ stroke: '#1976d2', strokeWidth: 2 }}
                  name="Number of Attacks"
                />
              </LineChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        {/* Attack Type Distribution */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Attack Type Distribution
            </Typography>
            {chartData.attackTypes.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={chartData.attackTypes}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(1)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {chartData.attackTypes.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip formatter={(value) => [`${value} attacks`, 'Count']} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <Box sx={{ height: 300, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Typography color="textSecondary">No attack data available</Typography>
              </Box>
            )}
          </Paper>
        </Grid>

        {/* System Summary */}
        <Grid item xs={12}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              System Summary
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="body2" color="textSecondary">
                  <strong>Current Status:</strong> {stats?.current_threat_level || 'Normal'}
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  <strong>Last Updated:</strong> {new Date().toLocaleString()}
                </Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="body2" color="textSecondary">
                  <strong>MITRE Techniques Detected:</strong> {Object.keys(stats?.mitre_techniques || {}).length}
                </Typography>
                <Typography variant="body2" color="textSecondary">
                  <strong>Top Attack Type:</strong> {Object.entries(stats?.attack_distribution || {})[0]?.[0] || 'None'}
                </Typography>
              </Grid>
            </Grid>
          </Paper>
        </Grid>

        {/* Quick Actions */}
        <Grid item xs={12}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Quick Actions
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6} md={3}>
                <Paper sx={{ p: 2, textAlign: 'center', cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
                  onClick={() => window.location.href = '/upload'}>
                  <Typography variant="body1" color="primary">Upload Logs</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Paper sx={{ p: 2, textAlign: 'center', cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
                  onClick={() => window.location.href = '/analysis'}>
                  <Typography variant="body1" color="primary">View Analysis</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Paper sx={{ p: 2, textAlign: 'center', cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
                  onClick={() => window.location.href = '/connect'}>
                  <Typography variant="body1" color="primary">Connect Honeypot</Typography>
                </Paper>
              </Grid>

            </Grid>
          </Paper>
        </Grid>
      </Grid>
    </Container>
  );
};

export default Dashboard;