import React, { useRef } from "react";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import LinearProgress from "@mui/material/LinearProgress";

export default function FileUploader({ file, onFile, options, onOptions, onStart, processing, uploadProgress }) {
  const inputRef = useRef();

  const handlePick = (e) => {
    const f = e.target.files[0];
    if (f) onFile(f);
  };

  return (
    <Box>
      <Typography variant="h6">Upload source file</Typography>
      <Box mt={1} display="flex" gap={2} alignItems="center">
        <Button variant="outlined" startIcon={<UploadFileIcon />} onClick={() => inputRef.current.click()}>
          Choose file
        </Button>
        <input ref={inputRef} type="file" hidden onChange={handlePick} accept=".py,.js,.ts,.java,.go,.c,.cpp,.cs,.txt" />
        <Typography color="text.secondary">{file ? file.name : "No file selected"}</Typography>
      </Box>

      <Box mt={2} display="grid" gap={2}>
        <TextField
          label="Chunk lines"
          type="number"
          value={options.chunkLines}
          onChange={(e) => onOptions({ ...options, chunkLines: Math.max(10, Number(e.target.value || 0)) })}
        />
        <TextField
          label="Overlap lines"
          type="number"
          value={options.overlap}
          onChange={(e) => onOptions({ ...options, overlap: Math.max(0, Number(e.target.value || 0)) })}
        />
      </Box>

      <Box mt={3} display="flex" gap={2}>
        <Button disabled={!file || processing} variant="contained" onClick={onStart}>
          {processing ? "Processing…" : "Start summarization"}
        </Button>
        <Button color="inherit" onClick={() => onFile(null)}>Clear</Button>
      </Box>

      {processing && (
        <Box mt={2}>
          <Typography variant="body2" color="text.secondary">Uploading / processing…</Typography>
          <LinearProgress variant="determinate" value={uploadProgress} />
        </Box>
      )}
    </Box>
  );
}
