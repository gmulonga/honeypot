import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Grid,
  Box,
  Card,
  CardContent,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Chip,
  Alert,
  CircularProgress,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from '@mui/material';
import {
  Timeline,
  Map,
  Security,
  TrendingUp,
  LocationOn,
  Refresh,
  Download,
  Visibility,
  BarChart,
  PieChart,
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  BarChart as ReBarChart,
  Bar,
  PieChart as RePieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as ReTooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { analyzeLogs, generateStixReport, downloadReport, getUploadedFiles, getFileAnalysis, getFileAttackLogs } from '../../services/api';
import toast from 'react-hot-toast';

const AnalysisDashboard = () => {
  const [timeRange, setTimeRange] = useState('24h');
  const [analysisData, setAnalysisData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [uploadedFiles, setUploadedFiles] = useState([]);
  const [selectedFileId, setSelectedFileId] = useState(null);
  const [fileAnalysis, setFileAnalysis] = useState(null);
  const [attackLogs, setAttackLogs] = useState([]);
  const [activeTab, setActiveTab] = useState(0);
  const [filter, setFilter] = useState({
    startDate: '',
    endDate: '',
    minSeverity: 1,
    attackTypes: [],
  });
  const [statsDialogOpen, setStatsDialogOpen] = useState(false);

  // Load uploaded files on mount
  useEffect(() => {
    fetchUploadedFiles();
  }, []);

  // Load file analysis when a file is selected
  useEffect(() => {
    if (selectedFileId) {
      loadFileAnalysis(selectedFileId);
      loadAttackLogs(selectedFileId);
    }
  }, [selectedFileId]);

  const fetchUploadedFiles = async () => {
    try {
      const response = await getUploadedFiles();
      setUploadedFiles(response.files || []);

      // Select the first file if available
      if (response.files && response.files.length > 0 && !selectedFileId) {
        setSelectedFileId(response.files[0].id);
      }
    } catch (error) {
      console.error('Error fetching uploaded files:', error);
      toast.error('Failed to load uploaded files');
    }
  };

  const loadFileAnalysis = async (fileId) => {
    try {
      const response = await getFileAnalysis(fileId);
      setFileAnalysis(response);
    } catch (error) {
      console.error('Error loading file analysis:', error);
      toast.error('Failed to load analysis for selected file');
    }
  };

  const loadAttackLogs = async (fileId) => {
    try {
      const response = await getFileAttackLogs(fileId, 0, 50);
      setAttackLogs(response.attack_logs || []);
    } catch (error) {
      console.error('Error loading attack logs:', error);
    }
  };

  const handleAnalyze = async () => {
    if (!filter.startDate || !filter.endDate) {
      toast.error('Please select start and end dates');
      return;
    }

    setLoading(true);
    try {
      const request = {
        start_date: new Date(filter.startDate).toISOString(),
        end_date: new Date(filter.endDate).toISOString(),
        min_severity: filter.minSeverity,
        attack_types: filter.attackTypes,
      };

      const response = await analyzeLogs(request);
      setAnalysisData(response);
      setStatsDialogOpen(true);
      toast.success('Analysis completed successfully!');
    } catch (error) {
      console.error('Analysis error:', error);
      toast.error('Error performing analysis: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateSTIX = async () => {
    if (!fileAnalysis?.has_stix_report) {
      toast.error('No STIX data available for this file');
      return;
    }

    try {
      const response = await generateStixReport([]); // You might want to pass specific attack IDs

      // Download the STIX file
      const dataStr = JSON.stringify(response.stix_bundle, null, 2);
      const dataBlob = new Blob([dataStr], { type: 'application/json' });
      const url = URL.createObjectURL(dataBlob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `stix-analysis-${Date.now()}.json`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      toast.success('STIX report generated and downloaded!');
    } catch (error) {
      toast.error('Error generating STIX report: ' + error.message);
    }
  };

  const handleExportCSV = async () => {
    try {
      await downloadReport('csv');
      toast.success('CSV report downloaded!');
    } catch (error) {
      toast.error('Error downloading CSV report: ' + error.message);
    }
  };

  // Prepare chart data from file analysis
  const prepareChartData = () => {
    if (!fileAnalysis?.analysis) {
      return {
        attackTypes: [],
        timeline: [],
        severityDistribution: [],
      };
    }

    // Attack type distribution
    const attackTypes = Object.entries(fileAnalysis.analysis.attack_distribution || {})
      .map(([name, value]) => ({
        name: name.replace('_', ' ').toUpperCase(),
        value,
      }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);

    // Timeline data (use hourly pattern if available)
    const timeline = fileAnalysis.analysis.hourly_pattern
      ? Object.entries(fileAnalysis.analysis.hourly_pattern).map(([hour, attacks]) => ({
        hour: `${hour}:00`,
        attacks,
      })).sort((a, b) => parseInt(a.hour) - parseInt(b.hour))
      : Array.from({ length: 24 }, (_, i) => ({
        hour: `${i}:00`,
        attacks: 0,
      }));

    // Severity distribution (simplified)
    const severityDistribution = [
      { name: 'Low (1-3)', value: Math.floor(fileAnalysis.analysis.total_attacks * 0.3) },
      { name: 'Medium (4-6)', value: Math.floor(fileAnalysis.analysis.total_attacks * 0.4) },
      { name: 'High (7-8)', value: Math.floor(fileAnalysis.analysis.total_attacks * 0.2) },
      { name: 'Critical (9-10)', value: Math.floor(fileAnalysis.analysis.total_attacks * 0.1) },
    ];

    return { attackTypes, timeline, severityDistribution };
  };

  const { attackTypes, timeline, severityDistribution } = prepareChartData();

  // Colors for charts
  const chartColors = ['#8884d8', '#82ca9d', '#ffc658', '#ff8042', '#0088fe', '#00C49F', '#FFBB28', '#FF8042'];

  const handleFileSelect = (fileId) => {
    setSelectedFileId(fileId);
    setActiveTab(0); // Switch to overview tab
  };

  if (loading && !analysisData) {
    return (
      <Container sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '80vh' }}>
        <CircularProgress />
      </Container>
    );
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      <Grid container spacing={3}>
        {/* Header */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Box>
                <Typography variant="h4" gutterBottom>
                  Threat Analysis
                </Typography>
                <Typography variant="body1" color="textSecondary">
                  Analyze attack patterns and generate threat intelligence
                </Typography>
              </Box>
              <FormControl sx={{ minWidth: 150 }}>
                <InputLabel>Time Range</InputLabel>
                <Select
                  value={timeRange}
                  label="Time Range"
                  onChange={(e) => setTimeRange(e.target.value)}
                >
                  <MenuItem value="1h">Last Hour</MenuItem>
                  <MenuItem value="24h">Last 24 Hours</MenuItem>
                  <MenuItem value="7d">Last 7 Days</MenuItem>
                  <MenuItem value="30d">Last 30 Days</MenuItem>
                </Select>
              </FormControl>
            </Box>
          </Paper>
        </Grid>

        {/* File Selection Panel */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 2, height: '100%' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h6">Uploaded Files</Typography>
              <IconButton size="small" onClick={fetchUploadedFiles}>
                <Refresh />
              </IconButton>
            </Box>

            {uploadedFiles.length === 0 ? (
              <Alert severity="info">
                No files uploaded yet. Upload log files to analyze.
              </Alert>
            ) : (
              <Box sx={{ maxHeight: 400, overflow: 'auto' }}>
                {uploadedFiles.map((file) => (
                  <Card
                    key={file.id}
                    sx={{
                      mb: 1,
                      cursor: 'pointer',
                      backgroundColor: selectedFileId === file.id ? 'action.selected' : 'background.paper',
                      '&:hover': {
                        backgroundColor: 'action.hover',
                      },
                    }}
                    onClick={() => handleFileSelect(file.id)}
                  >
                    <CardContent sx={{ py: 1, '&:last-child': { pb: 1 } }}>
                      <Typography variant="body2" fontWeight="medium">
                        {file.filename}
                      </Typography>
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 0.5 }}>
                        <Chip
                          label={file.honeypot_type}
                          size="small"
                          variant="outlined"
                        />
                        <Typography variant="caption" color="textSecondary">
                          {new Date(file.uploaded_at).toLocaleDateString()}
                        </Typography>
                      </Box>
                      {file.description && (
                        <Typography variant="caption" color="textSecondary" sx={{ mt: 0.5, display: 'block' }}>
                          {file.description}
                        </Typography>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </Box>
            )}
          </Paper>
        </Grid>

        {/* Main Analysis Panel */}
        <Grid item xs={12} md={8}>
          <Paper sx={{ p: 2, height: '100%' }}>
            {!selectedFileId ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 300 }}>
                <Typography color="textSecondary">
                  Select a file to view analysis
                </Typography>
              </Box>
            ) : !fileAnalysis ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 300 }}>
                <CircularProgress />
              </Box>
            ) : (
              <>
                <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
                  <Tabs value={activeTab} onChange={(e, newValue) => setActiveTab(newValue)}>
                    <Tab label="Overview" icon={<BarChart />} iconPosition="start" />
                    <Tab label="Attack Logs" icon={<Visibility />} iconPosition="start" />
                    <Tab label="Charts" icon={<PieChart />} iconPosition="start" />
                  </Tabs>
                </Box>

                {activeTab === 0 && (
                  <Box>
                    {/* Quick Stats */}
                    <Grid container spacing={2} sx={{ mb: 3 }}>
                      <Grid item xs={6} md={3}>
                        <Card>
                          <CardContent sx={{ textAlign: 'center' }}>
                            <Timeline color="primary" sx={{ mb: 1 }} />
                            <Typography variant="h5">{fileAnalysis.analysis.total_attacks}</Typography>
                            <Typography variant="caption" color="textSecondary">Total Attacks</Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                      <Grid item xs={6} md={3}>
                        <Card>
                          <CardContent sx={{ textAlign: 'center' }}>
                            <Security color="error" sx={{ mb: 1 }} />
                            <Typography variant="h5">{fileAnalysis.analysis.high_severity_attacks}</Typography>
                            <Typography variant="caption" color="textSecondary">High Severity</Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                      <Grid item xs={6} md={3}>
                        <Card>
                          <CardContent sx={{ textAlign: 'center' }}>
                            <TrendingUp color="warning" sx={{ mb: 1 }} />
                            <Typography variant="h5">{fileAnalysis.analysis.unique_attackers}</Typography>
                            <Typography variant="caption" color="textSecondary">Unique Attackers</Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                      <Grid item xs={6} md={3}>
                        <Card>
                          <CardContent sx={{ textAlign: 'center' }}>
                            <Map color="success" sx={{ mb: 1 }} />
                            <Typography variant="h5">{fileAnalysis.analysis.average_severity?.toFixed(1) || '0.0'}</Typography>
                            <Typography variant="caption" color="textSecondary">Avg. Severity</Typography>
                          </CardContent>
                        </Card>
                      </Grid>
                    </Grid>

                    {/* Attack Distribution */}
                    <Typography variant="subtitle1" gutterBottom>
                      Attack Distribution
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 3 }}>
                      {Object.entries(fileAnalysis.analysis.attack_distribution || {})
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 8)
                        .map(([type, count]) => (
                          <Chip
                            key={type}
                            label={`${type.replace('_', ' ')}: ${count}`}
                            color="primary"
                            variant="outlined"
                          />
                        ))}
                    </Box>

                    {/* MITRE Techniques */}
                    <Typography variant="subtitle1" gutterBottom>
                      MITRE ATT&CK Techniques
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                      {Object.entries(fileAnalysis.analysis.mitre_techniques || {}).map(([tech, count]) => (
                        <Chip
                          key={tech}
                          label={`${tech}: ${count}`}
                          color="secondary"
                          variant="outlined"
                          size="small"
                        />
                      ))}
                    </Box>
                  </Box>
                )}

                {activeTab === 1 && (
                  <Box>
                    <Typography variant="subtitle1" gutterBottom>
                      Recent Attack Logs ({attackLogs.length} shown)
                    </Typography>
                    <TableContainer sx={{ maxHeight: 400 }}>
                      <Table size="small" stickyHeader>
                        <TableHead>
                          <TableRow>
                            <TableCell>Time</TableCell>
                            <TableCell>Source IP</TableCell>
                            <TableCell>Type</TableCell>
                            <TableCell>Severity</TableCell>
                            <TableCell>Port</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {attackLogs.map((log) => (
                            <TableRow key={log.id} hover>
                              <TableCell>
                                {new Date(log.timestamp).toLocaleTimeString()}
                              </TableCell>
                              <TableCell>
                                <Typography variant="body2">{log.source_ip}</Typography>
                                {log.country && (
                                  <Typography variant="caption" color="textSecondary">
                                    {log.country}
                                  </Typography>
                                )}
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={log.attack_type}
                                  size="small"
                                  color={
                                    log.severity >= 8 ? 'error' :
                                      log.severity >= 6 ? 'warning' : 'default'
                                  }
                                  variant="outlined"
                                />
                              </TableCell>
                              <TableCell>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                  <Typography variant="body2">{log.severity}/10</Typography>
                                  <LinearProgress
                                    variant="determinate"
                                    value={log.severity * 10}
                                    sx={{ width: 50, height: 6, borderRadius: 3 }}
                                    color={
                                      log.severity >= 8 ? 'error' :
                                        log.severity >= 6 ? 'warning' : 'success'
                                    }
                                  />
                                </Box>
                              </TableCell>
                              <TableCell>{log.port || '-'}</TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  </Box>
                )}

                {activeTab === 2 && (
                  <Grid container spacing={3}>
                    {/* Attack Timeline */}
                    <Grid item xs={12}>
                      <Typography variant="subtitle1" gutterBottom>
                        Attack Timeline
                      </Typography>
                      <ResponsiveContainer width="100%" height={200}>
                        <LineChart data={timeline}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="hour" />
                          <YAxis />
                          <ReTooltip />
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
                    </Grid>

                    {/* Attack Type Distribution */}
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle1" gutterBottom>
                        Attack Type Distribution
                      </Typography>
                      <ResponsiveContainer width="100%" height={250}>
                        <RePieChart>
                          <Pie
                            data={attackTypes}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(1)}%`}
                            outerRadius={80}
                            fill="#8884d8"
                            dataKey="value"
                          >
                            {attackTypes.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={chartColors[index % chartColors.length]} />
                            ))}
                          </Pie>
                          <ReTooltip formatter={(value) => [`${value} attacks`, 'Count']} />
                        </RePieChart>
                      </ResponsiveContainer>
                    </Grid>

                    {/* Severity Distribution */}
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle1" gutterBottom>
                        Severity Distribution
                      </Typography>
                      <ResponsiveContainer width="100%" height={250}>
                        <ReBarChart data={severityDistribution}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="name" />
                          <YAxis />
                          <ReTooltip />
                          <Bar dataKey="value" fill="#82ca9d" name="Number of Attacks" />
                        </ReBarChart>
                      </ResponsiveContainer>
                    </Grid>
                  </Grid>
                )}
              </>
            )}
          </Paper>
        </Grid>

        {/* Analysis Filters */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Advanced Analysis Filters
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={3}>
                <TextField
                  fullWidth
                  label="Start Date"
                  type="date"
                  value={filter.startDate}
                  onChange={(e) => setFilter({ ...filter, startDate: e.target.value })}
                  InputLabelProps={{ shrink: true }}
                />
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField
                  fullWidth
                  label="End Date"
                  type="date"
                  value={filter.endDate}
                  onChange={(e) => setFilter({ ...filter, endDate: e.target.value })}
                  InputLabelProps={{ shrink: true }}
                />
              </Grid>
              <Grid item xs={12} md={2}>
                <TextField
                  fullWidth
                  label="Min Severity"
                  type="number"
                  value={filter.minSeverity}
                  onChange={(e) => setFilter({ ...filter, minSeverity: parseInt(e.target.value) })}
                  InputProps={{ inputProps: { min: 1, max: 10 } }}
                />
              </Grid>
              <Grid item xs={12} md={2}>
                <FormControl fullWidth>
                  <InputLabel>Attack Type</InputLabel>
                  <Select
                    multiple
                    value={filter.attackTypes}
                    label="Attack Type"
                    onChange={(e) => setFilter({ ...filter, attackTypes: e.target.value })}
                    renderValue={(selected) => selected.join(', ')}
                  >
                    <MenuItem value="brute_force">Brute Force</MenuItem>
                    <MenuItem value="port_scan">Port Scan</MenuItem>
                    <MenuItem value="malware">Malware</MenuItem>
                    <MenuItem value="ddos">DDoS</MenuItem>
                    <MenuItem value="exploit">Exploit</MenuItem>
                    <MenuItem value="phishing">Phishing</MenuItem>
                    <MenuItem value="sql_injection">SQL Injection</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={2}>
                <Button
                  variant="contained"
                  onClick={handleAnalyze}
                  disabled={loading}
                  fullWidth
                  sx={{ height: '56px' }}
                >
                  {loading ? <CircularProgress size={24} /> : 'Run Analysis'}
                </Button>
              </Grid>
            </Grid>
          </Paper>
        </Grid>

        {/* Action Buttons */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Generate Reports
            </Typography>
            <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
              <Button
                variant="contained"
                color="primary"
                onClick={handleGenerateSTIX}
                disabled={!fileAnalysis?.has_stix_report}
                startIcon={<Download />}
              >
                Download STIX Report
              </Button>

            </Box>
          </Paper>
        </Grid>
      </Grid>

      {/* Analysis Results Dialog */}
      <Dialog
        open={statsDialogOpen}
        onClose={() => setStatsDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        {analysisData && (
          <>
            <DialogTitle>
              Advanced Analysis Results
            </DialogTitle>
            <DialogContent dividers>
              <Grid container spacing={2}>
                <Grid item xs={12}>
                  <Typography variant="subtitle1" gutterBottom>
                    Analysis Summary
                  </Typography>
                  <Grid container spacing={2}>
                    <Grid item xs={6} md={3}>
                      <Typography variant="caption" color="textSecondary">Total Attacks</Typography>
                      <Typography variant="h6">{analysisData.total_attacks}</Typography>
                    </Grid>
                    <Grid item xs={6} md={3}>
                      <Typography variant="caption" color="textSecondary">Unique Attackers</Typography>
                      <Typography variant="h6">{analysisData.unique_attackers}</Typography>
                    </Grid>
                    <Grid item xs={6} md={3}>
                      <Typography variant="caption" color="textSecondary">Attack Types</Typography>
                      <Typography variant="h6">{Object.keys(analysisData.attack_distribution || {}).length}</Typography>
                    </Grid>
                    <Grid item xs={6} md={3}>
                      <Typography variant="caption" color="textSecondary">MITRE Techniques</Typography>
                      <Typography variant="h6">{Object.keys(analysisData.mitre_coverage || {}).length}</Typography>
                    </Grid>
                  </Grid>
                </Grid>

                {analysisData.attack_distribution && (
                  <Grid item xs={12}>
                    <Typography variant="subtitle1" gutterBottom>
                      Attack Distribution
                    </Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                      {Object.entries(analysisData.attack_distribution)
                        .sort((a, b) => b[1] - a[1])
                        .slice(0, 10)
                        .map(([type, count]) => (
                          <Chip
                            key={type}
                            label={`${type.replace('_', ' ')}: ${count}`}
                            size="small"
                            color="primary"
                            variant="outlined"
                          />
                        ))}
                    </Box>
                  </Grid>
                )}
              </Grid>
            </DialogContent>
            <DialogActions>
              <Button onClick={() => setStatsDialogOpen(false)}>Close</Button>
            </DialogActions>
          </>
        )}
      </Dialog>
    </Container>
  );
};

export default AnalysisDashboard;