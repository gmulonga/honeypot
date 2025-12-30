import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  CircularProgress,
  Alert,
  Grid,
  Chip,
  Divider,
  LinearProgress,
  Container,
} from '@mui/material';
import { useDropzone } from 'react-dropzone';
import { uploadFile, downloadReport } from '../../services/api';
import toast from 'react-hot-toast';

const LogUpload = () => {
  const [file, setFile] = useState(null);
  const [honeypotType, setHoneypotType] = useState('t-pot');
  const [description, setDescription] = useState('');
  const [loading, setLoading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [analysisResult, setAnalysisResult] = useState(null);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: {
      'application/json': ['.json'],
      'text/plain': ['.log', '.txt']
    },
    maxFiles: 1,
    maxSize: 100 * 1024 * 1024, // 100MB
    onDrop: (acceptedFiles, rejectedFiles) => {
      if (rejectedFiles.length > 0) {
        toast.error(`File rejected: ${rejectedFiles[0].errors[0].message}`);
        return;
      }
      setFile(acceptedFiles[0]);
      setAnalysisResult(null); // Clear previous results
    },
  });

  const handleUpload = async () => {
    if (!file) {
      toast.error('Please select a file first');
      return;
    }

    setLoading(true);
    setUploadProgress(0);

    try {
      const response = await uploadFile(file, honeypotType, description);

      // Simulate progress for better UX
      const progressInterval = setInterval(() => {
        setUploadProgress((prev) => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + 10;
        });
      }, 300);

      setAnalysisResult(response.data.data);
      setUploadProgress(100);
      clearInterval(progressInterval);

      toast.success('File uploaded and analyzed successfully!');

    } catch (error) {
      toast.error('Error uploading file: ' + (error.response?.data?.detail || error.message));
    } finally {
      setLoading(false);
      setTimeout(() => setUploadProgress(0), 1000);
    }
  };

  const handleDownloadSTIX = () => {
    if (!analysisResult?.stix_bundle) {
      toast.error('No STIX data available');
      return;
    }

    const dataStr = JSON.stringify(analysisResult.stix_bundle, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `stix-report-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    toast.success('STIX report downloaded!');
  };

  const handleDownloadReport = async (type) => {
    try {
      if (!analysisResult) {
        toast.error('No analysis results available');
        return;
      }

      let data, filename, mimeType;

      if (type === 'stix') {
        data = JSON.stringify(analysisResult.stix_bundle || analysisResult, null, 2);
        filename = `stix-report-${Date.now()}.json`;
        mimeType = 'application/json';
      } else if (type === 'csv') {
        const csvData = convertAnalysisToCSV(analysisResult);
        data = csvData;
        filename = `honeypot-report-${Date.now()}.csv`;
        mimeType = 'text/csv';
      }

      const blob = new Blob([data], { type: mimeType });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      toast.success(`${type.toUpperCase()} report downloaded successfully!`);
    } catch (error) {
      toast.error('Error downloading report: ' + error.message);
    }
  };

  const convertAnalysisToCSV = (analysisResult) => {
    const headers = ['Metric', 'Value'];
    const rows = [];

    if (analysisResult.analysis) {
      Object.entries(analysisResult.analysis).forEach(([key, value]) => {
        if (typeof value === 'object') {
          rows.push([key, JSON.stringify(value)]);
        } else {
          rows.push([key, value]);
        }
      });
    }

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.join(','))
    ].join('\n');

    return csvContent;
  };

  const handleViewAnalysis = () => {
    if (analysisResult) {
      localStorage.setItem('lastAnalysis', JSON.stringify(analysisResult));
      window.location.href = '/analysis';
    } else {
      toast.error('No analysis results to view');
    }
  };

  return (
    <Container
      disableGutters
      maxWidth={false}
      sx={{
        mt: 4,
        mb: 4,
        px: { xs: 2, sm: 3, md: 4 },
        width: '100%',
        maxWidth: '100% !important',
      }}
    >
      <Paper
        sx={{
          p: { xs: 2, sm: 3, md: 4 },
          width: '100%',
          maxWidth: '100%',
          overflow: 'visible',
          boxSizing: 'border-box',
        }}
      >
        <Typography variant="h4" gutterBottom>
          Upload Honeypot Logs
        </Typography>
        <Typography variant="body1" color="textSecondary" paragraph>
          Upload JSON log files from your honeypot deployment for analysis
        </Typography>

        {/* Dropzone - Full width */}
        <Box
          {...getRootProps()}
          sx={{
            border: '2px dashed',
            borderColor: isDragActive ? 'primary.main' : 'grey.700',
            borderRadius: 2,
            p: { xs: 3, sm: 4, md: 6 },
            textAlign: 'center',
            cursor: 'pointer',
            backgroundColor: isDragActive ? 'action.hover' : 'background.paper',
            transition: 'all 0.2s',
            mb: 4,
            width: '100%',
            minHeight: 200,
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'center',
            alignItems: 'center',
            boxSizing: 'border-box',
          }}
        >
          <input {...getInputProps()} />
          <Typography variant="h6" sx={{ mb: 1 }}>
            {file ? (
              <>
                Selected: <strong>{file.name}</strong> ({(file.size / 1024).toFixed(2)} KB)
              </>
            ) : (
              'Drag & drop a JSON log file here, or click to select'
            )}
          </Typography>
          <Typography variant="caption" color="textSecondary">
            Supports: .json, .log, .txt files (Max 100MB)
          </Typography>
        </Box>

        {/* Upload Progress */}
        {loading && uploadProgress > 0 && (
          <Box sx={{ width: '100%', mb: 3 }}>
            <LinearProgress
              variant="determinate"
              value={uploadProgress}
              sx={{ height: 10, borderRadius: 5 }}
            />
            <Typography variant="caption" sx={{ mt: 1, display: 'block', textAlign: 'center' }}>
              {uploadProgress < 100 ? 'Uploading and analyzing...' : 'Analysis complete!'}
            </Typography>
          </Box>
        )}

        {/* Form Controls - Full width grid */}
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <FormControl fullWidth size="medium">
              <InputLabel>Honeypot Type</InputLabel>
              <Select
                value={honeypotType}
                label="Honeypot Type"
                onChange={(e) => setHoneypotType(e.target.value)}
              >
                <MenuItem value="t-pot">T-Pot</MenuItem>
                <MenuItem value="cowrie">Cowrie</MenuItem>
                <MenuItem value="dionaea">Dionaea</MenuItem>
                <MenuItem value="glutton">Glutton</MenuItem>
                <MenuItem value="custom">Custom</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              label="Description (Optional)"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="E.g., Cowrie logs from Kenyan server"
              size="medium"
            />
          </Grid>
        </Grid>

        {/* Upload Button - Full width */}
        <Button
          variant="contained"
          onClick={handleUpload}
          disabled={!file || loading}
          fullWidth
          size="large"
          sx={{
            mt: 4,
            mb: 4,
            py: 2,
            fontSize: '1.1rem',
          }}
        >
          {loading ? (
            <>
              <CircularProgress size={28} sx={{ mr: 2 }} />
              Uploading & Analyzing...
            </>
          ) : (
            'Upload & Analyze Log File'
          )}
        </Button>

        {/* Analysis Results - Full width */}
        {analysisResult && (
          <Box sx={{ mt: 4, width: '100%' }}>
            <Alert severity="success" sx={{ mb: 3, fontSize: '1rem' }}>
              ✓ Analysis completed successfully! Found {analysisResult.analysis?.total_attacks || 0} attacks.
            </Alert>

            {/* Quick Stats - Full width grid */}
            {analysisResult.analysis && (
              <Paper sx={{ p: 4, mb: 4, bgcolor: 'background.default', width: '100%', boxSizing: 'border-box' }}>
                <Typography variant="h5" gutterBottom>
                  Analysis Results
                </Typography>
                <Grid container spacing={3} sx={{ mb: 3 }}>
                  {[
                    { label: 'Total Attacks', value: analysisResult.analysis.total_attacks },
                    { label: 'Unique Attackers', value: analysisResult.analysis.unique_attackers },
                    { label: 'High Severity', value: analysisResult.analysis.high_severity_attacks },
                    { label: 'Avg. Severity', value: analysisResult.analysis.average_severity?.toFixed(1) },
                  ].map((stat, index) => (
                    <Grid item xs={12} sm={6} md={3} key={index}>
                      <Typography variant="subtitle2" color="textSecondary" display="block" gutterBottom>
                        {stat.label}
                      </Typography>
                      <Typography variant="h3" sx={{ fontWeight: 'bold' }}>
                        {stat.value}
                      </Typography>
                    </Grid>
                  ))}
                </Grid>

                {/* Attack Distribution */}
                <Divider sx={{ my: 3 }} />
                <Typography variant="h6" gutterBottom>
                  Attack Distribution
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mt: 2 }}>
                  {Object.entries(analysisResult.analysis.attack_distribution || {})
                    .sort((a, b) => b[1] - a[1])
                    .map(([type, count]) => (
                      <Chip
                        key={type}
                        label={`${type.replace('_', ' ').toUpperCase()}: ${count}`}
                        color="primary"
                        variant="filled"
                        size="medium"
                        sx={{ fontSize: '0.9rem', py: 1 }}
                      />
                    ))}
                </Box>

                {/* MITRE Techniques */}
                <Divider sx={{ my: 3 }} />
                <Typography variant="h6" gutterBottom>
                  MITRE ATT&CK Techniques Detected
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mt: 2 }}>
                  {Object.entries(analysisResult.analysis.mitre_techniques || {}).map(([tech, count]) => (
                    <Chip
                      key={tech}
                      label={`${tech}: ${count} attacks`}
                      color="secondary"
                      variant="filled"
                      size="medium"
                      sx={{ fontSize: '0.9rem', py: 1 }}
                    />
                  ))}
                </Box>
              </Paper>
            )}

            {/* Action Buttons - Full width */}
            <Box sx={{
              display: 'flex',
              gap: 3,
              flexWrap: 'wrap',
              justifyContent: 'center',
              mt: 4,
              width: '100%',
            }}>
              <Button
                variant="contained"
                onClick={handleDownloadSTIX}
                disabled={!analysisResult?.stix_bundle}
                size="large"
                sx={{
                  minWidth: { xs: '100%', sm: 200 },
                  py: 1.5,
                  flex: { xs: '1 0 100%', sm: '0 1 auto' }
                }}
              >
                Download STIX Bundle
              </Button>
              <Button
                variant="outlined"
                onClick={() => handleDownloadReport('stix')}
                disabled={!analysisResult}
                size="large"
                sx={{
                  minWidth: { xs: '100%', sm: 200 },
                  py: 1.5,
                  flex: { xs: '1 0 100%', sm: '0 1 auto' }
                }}
              >
                Download STIX Report
              </Button>
              <Button
                variant="outlined"
                onClick={() => handleDownloadReport('csv')}
                disabled={!analysisResult}
                size="large"
                sx={{
                  minWidth: { xs: '100%', sm: 200 },
                  py: 1.5,
                  flex: { xs: '1 0 100%', sm: '0 1 auto' }
                }}
              >
                Export to CSV
              </Button>
              <Button
                variant="outlined"
                onClick={handleViewAnalysis}
                disabled={!analysisResult}
                size="large"
                sx={{
                  minWidth: { xs: '100%', sm: 200 },
                  py: 1.5,
                  flex: { xs: '1 0 100%', sm: '0 1 auto' }
                }}
              >
                View Detailed Analysis
              </Button>
            </Box>
          </Box>
        )}
      </Paper>
    </Container>
  );
};

export default LogUpload;