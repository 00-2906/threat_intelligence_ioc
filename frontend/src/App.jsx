import React, { useState } from "react";
import Container from "@mui/material/Container";
import Box from "@mui/material/Box";
import Typography from "@mui/material/Typography";
import Paper from "@mui/material/Paper";
import Grid from "@mui/material/Grid";
import Divider from "@mui/material/Divider";
import FileUploader from "./components/FileUploader";
import SummaryPanel from "./components/SummaryPanel";
import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000/api/summarize";

export default function App() {
  const [file, setFile] = useState(null);
  const [options, setOptions] = useState({ chunkLines: 250, overlap: 5 });
  const [processing, setProcessing] = useState(false);
  const [result, setResult] = useState(null);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [error, setError] = useState(null);

  const handleStart = async () => {
    if (!file) return;
    setProcessing(true);
    setResult(null);
    setError(null);
    setUploadProgress(0);

    const form = new FormData();
    form.append("file", file);
    form.append("chunk_lines", String(options.chunkLines));
    form.append("overlap_lines", String(options.overlap));

    try {
      const resp = await axios.post(API_URL, form, {
        headers: { "Content-Type": "multipart/form-data" },
        onUploadProgress: (ev) => {
          if (ev.lengthComputable) setUploadProgress(Math.round((ev.loaded / ev.total) * 100));
          else setUploadProgress(10);
        },
        timeout: 120000,
      });
      setResult(resp.data);
    } catch (err) {
      console.error(err);
      setError(err?.response?.data?.detail || err?.response?.data?.message || err.message || "Upload failed");
    } finally {
      setProcessing(false);
      setUploadProgress(0);
    }
  };

  return (
    <Container maxWidth="xl" sx={{ py: 4 }}>
      <Typography variant="h4" gutterBottom>Code Insight — Instant Summaries</Typography>
      <Typography color="text.secondary" gutterBottom>
        Polished frontend for fast summarization, previews, and downloads — ready for hackathons.
      </Typography>

      <Paper sx={{ p: 3, mt: 2 }}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={5}>
            <FileUploader
              file={file}
              onFile={setFile}
              options={options}
              onOptions={setOptions}
              onStart={handleStart}
              processing={processing}
              uploadProgress={uploadProgress}
            />
          </Grid>

          <Grid item xs={12} md={7}>
            <SummaryPanel
              file={file}
              result={result}
              processing={processing}
              error={error}
            />
          </Grid>
        </Grid>

        <Box mt={3}>
          <Divider />
          <Box mt={2} display="flex" justifyContent="space-between">
            <Typography variant="caption" color="text.secondary">
              Tip: Use smaller chunk sizes for very long or very dense files.
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Backend API: POST /api/summarize
            </Typography>
          </Box>
        </Box>
      </Paper>
    </Container>
  );
}
