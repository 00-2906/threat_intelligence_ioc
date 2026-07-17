import React from "react";
import Box from "@mui/material/Box";
import Typography from "@mui/material/Typography";
import Paper from "@mui/material/Paper";
import Button from "@mui/material/Button";
import IconButton from "@mui/material/IconButton";
import DownloadIcon from "@mui/icons-material/Download";
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { okaidia } from "react-syntax-highlighter/dist/esm/styles/prism";
import FileSaver from "file-saver";
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';

function downloadText(filename, text) {
  const blob = new Blob([text || ""], { type: "text/plain;charset=utf-8" });
  FileSaver.saveAs(blob, filename);
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text || "");
    return true;
  } catch (e) {
    // fallback
    const ta = document.createElement('textarea');
    ta.value = text || "";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (err) {}
    document.body.removeChild(ta);
    return false;
  }
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
          <Box display="flex" gap={1} alignItems="center" justifyContent="space-between">
            <Typography variant="body1" sx={{ whiteSpace: "pre-wrap", flex: 1 }}>{finalText || "No summary returned."}</Typography>
            <IconButton aria-label="copy-final" onClick={() => copyToClipboard(finalText)}>
              <ContentCopyIcon />
            </IconButton>
          </Box>
        </Box>
      </Paper>

      <Paper sx={{ p: 2, overflow: "auto", minHeight: 300 }}>
        <Typography variant="subtitle1">Chunk summaries</Typography>
        {chunks.length === 0 && <Typography color="text.secondary">No chunk summaries.</Typography>}
        {chunks.map((c, idx) => (
          <Accordion key={idx} defaultExpanded={idx===0} sx={{ mt: 1 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
              <Box display="flex" alignItems="center" justifyContent="space-between" width="100%">
                <Typography variant="subtitle2">Lines {c.start}–{c.end}</Typography>
                <Box>
                  <IconButton size="small" onClick={(e) => { e.stopPropagation(); copyToClipboard(c.summary); }} title="Copy chunk summary">
                    <ContentCopyIcon fontSize="small" />
                  </IconButton>
                </Box>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>{c.summary}</Typography>
            </AccordionDetails>
          </Accordion>
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
