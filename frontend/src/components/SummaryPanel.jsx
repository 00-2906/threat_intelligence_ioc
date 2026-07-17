import React from "react";
import Box from "@mui/material/Box";
import Typography from "@mui/material/Typography";
import Paper from "@mui/material/Paper";
import Button from "@mui/material/Button";
import DownloadIcon from "@mui/icons-material/Download";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { okaidia } from "react-syntax-highlighter/dist/esm/styles/prism";
import FileSaver from "file-saver";

function downloadText(filename, text) {
  const blob = new Blob([text || ""], { type: "text/plain;charset=utf-8" });
  FileSaver.saveAs(blob, filename);
}

export default function SummaryPanel({ file, result, processing, error }) {
  if (!file && !processing) {
    return (
      <Paper sx={{ p: 2, minHeight: 300 }}>
        <Typography variant="subtitle1">Preview and results</Typography>
        <Typography color="text.secondary">Choose a file and start summarization. Preview shows first 300 lines.</Typography>
      </Paper>
    );
  }

  if (error) {
    return (
      <Paper sx={{ p: 2 }}>
        <Typography variant="h6" color="error">Error</Typography>
        <Typography>{String(error)}</Typography>
      </Paper>
    );
  }

  if (processing && !result) {
    return (
      <Paper sx={{ p: 2, minHeight: 300 }}>
        <Typography variant="h6">Working…</Typography>
        <Typography color="text.secondary">The backend is summarizing your file. This may take a few seconds.</Typography>
      </Paper>
    );
  }

  const chunks = result?.chunks || [];
  const finalText = result?.final_summary || "";

  return (
    <Box display="grid" gridTemplateRows="auto 1fr" gap={2}>
      <Paper sx={{ p: 2 }}>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box>
            <Typography variant="h6">Final summary</Typography>
            <Typography color="text.secondary" variant="body2">{file?.name}</Typography>
          </Box>
          <Box>
            <Button variant="outlined" startIcon={<DownloadIcon />} onClick={() => downloadText(`${file?.name}.summary.txt`, finalText)}>
              Download summary
            </Button>
          </Box>
        </Box>
        <Box mt={1}>
          <Typography variant="body1" sx={{ whiteSpace: "pre-wrap" }}>{finalText || "No summary returned."}</Typography>
        </Box>
      </Paper>

      <Paper sx={{ p: 2, overflow: "auto", minHeight: 300 }}>
        <Typography variant="subtitle1">Chunk summaries</Typography>
        {chunks.length === 0 && <Typography color="text.secondary">No chunk summaries.</Typography>}
        {chunks.map((c, idx) => (
          <Box key={idx} mt={2} sx={{ borderLeft: "4px solid rgba(255,255,255,0.06)", pl: 2 }}>
            <Typography variant="subtitle2">Lines {c.start}–{c.end}</Typography>
            <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>{c.summary}</Typography>
          </Box>
        ))}

        <Box mt={3}>
          <Typography variant="subtitle2">Preview (first 300 lines)</Typography>
          <SyntaxHighlighter language="auto" style={okaidia} showLineNumbers wrapLongLines>
            {result?.preview || "// no preview available"}
          </SyntaxHighlighter>
        </Box>
      </Paper>
    </Box>
  );
}
