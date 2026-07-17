import React from "react";
import Box from "@mui/material/Box";
import Typography from "@mui/material/Typography";
import IconButton from "@mui/material/IconButton";
import Brightness4Icon from '@mui/icons-material/Brightness4';
import Brightness7Icon from '@mui/icons-material/Brightness7';
import Button from "@mui/material/Button";

export default function Header({ dark, setDark, onDemo }) {
  return (
    <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
      <Box>
        <Typography variant="h4" component="div">Code Insight — Instant Summaries</Typography>
        <Typography variant="caption" color="text.secondary">Upload source files, preview, and get fast summaries</Typography>
      </Box>

      <Box display="flex" alignItems="center" gap={1}>
        <Button variant="outlined" onClick={onDemo}>Try demo</Button>
        <IconButton onClick={() => setDark(!dark)} color="inherit" aria-label="toggle theme">
          {dark ? <Brightness7Icon/> : <Brightness4Icon/>}
        </IconButton>
      </Box>
    </Box>
  );
}
