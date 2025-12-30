import React from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Grid,
} from '@mui/material';
import {
  Timeline,
  Security,
  People,
  Public,
  TrendingUp,
  Speed,
} from '@mui/icons-material';

const StatsCards = ({ stats }) => {
  const statItems = [
    {
      title: 'Total Attacks',
      value: stats?.total_attacks || '0',
      icon: <Timeline color="primary" />,
      color: 'primary',
      description: 'Total detected attacks',
    },
    {
      title: 'High Severity',
      value: stats?.high_severity_attacks || '0',
      icon: <Security color="error" />,
      color: 'error',
      description: 'Critical threats',
    },
    {
      title: 'Unique Attackers',
      value: stats?.unique_attackers || '0',
      icon: <People color="warning" />,
      color: 'warning',
      description: 'Distinct source IPs',
    },
    {
      title: 'Threat Level',
      value: stats?.current_threat_level || 'Low',
      icon: <Speed color="info" />,
      color: 'info',
      description: 'Current security status',
    },
    {
      title: 'Avg. Severity',
      value: stats?.average_severity ? stats.average_severity.toFixed(1) : '0.0',
      icon: <TrendingUp sx={{ color: 'purple' }} />,
      color: 'secondary',
      description: 'Average attack severity',
    },
  ];

  return (
    <Grid container spacing={2} sx={{ mb: 3 }}>
      {statItems.map((item, index) => (
        <Grid item xs={12} sm={6} md={4} lg={2.4} key={index}>
          <Card
            sx={{
              height: '100%',
              display: 'flex',
              flexDirection: 'column',
              transition: 'transform 0.2s',
              '&:hover': {
                transform: 'translateY(-4px)',
                boxShadow: 3,
              },
            }}
          >
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Box
                  sx={{
                    p: 1,
                    borderRadius: 1,
                    backgroundColor: `${item.color}.light`,
                    mr: 1,
                  }}
                >
                  {item.icon}
                </Box>
                <Typography variant="subtitle2" color="textSecondary">
                  {item.title}
                </Typography>
              </Box>
              <Typography variant="h4" sx={{ fontWeight: 'bold', mb: 0.5 }}>
                {item.value}
              </Typography>
              <Typography variant="caption" color="textSecondary">
                {item.description}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      ))}
    </Grid>
  );
};

export default StatsCards;