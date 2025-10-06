"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { History, Trash2, Eye, RefreshCw, Clock, AlertCircle } from "lucide-react"
import { Alert, AlertDescription } from "@/components/ui/alert"

interface ScanHistoryItem {
  id: number
  target_url: string
  scan_time: string
  status: string
  summary: {
    total_pages_scanned: number
    total_forms_found: number
    sql_injection_vulnerabilities: number
    xss_vulnerabilities: number
    missing_security_headers: number
    security_warnings: number
  }
}

interface ScanHistoryProps {
  onViewScan: (scanId: number) => void
}

export function ScanHistory({ onViewScan }: ScanHistoryProps) {
  const [history, setHistory] = useState<ScanHistoryItem[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const fetchHistory = async () => {
    setLoading(true)
    setError("")

    try {
      const response = await fetch("http://localhost:5000/api/history")
      if (!response.ok) throw new Error("Failed to fetch history")

      const data = await response.json()
      setHistory(data.scans)
    } catch (err) {
      setError("Failed to load scan history")
    } finally {
      setLoading(false)
    }
  }

  const deleteScan = async (scanId: number) => {
    try {
      const response = await fetch(`http://localhost:5000/api/history/${scanId}`, {
        method: "DELETE",
      })

      if (!response.ok) throw new Error("Failed to delete scan")

      // Refresh history after deletion
      fetchHistory()
    } catch (err) {
      setError("Failed to delete scan")
    }
  }

  useEffect(() => {
    fetchHistory()
  }, [])

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleString()
  }

  const getTotalVulnerabilities = (scan: ScanHistoryItem) => {
    return scan.summary.sql_injection_vulnerabilities + scan.summary.xss_vulnerabilities
  }

  return (
    <Card className="border-border/50 bg-card/50 backdrop-blur-sm shadow-xl">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <History className="h-5 w-5 text-primary" />
              Scan History
            </CardTitle>
            <CardDescription className="mt-1">Previous security assessments and reports</CardDescription>
          </div>
          <Button
            onClick={fetchHistory}
            variant="outline"
            size="sm"
            disabled={loading}
            className="gap-2 bg-transparent border-border/50 hover:border-primary/50"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {error && (
          <Alert variant="destructive" className="mb-4 border-destructive/50 bg-destructive/10">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {history.length === 0 && !loading && (
          <div className="text-center py-12">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-muted/30 mb-4 border border-border/50">
              <History className="h-8 w-8 text-muted-foreground" />
            </div>
            <h3 className="text-lg font-semibold mb-2">No Scan History</h3>
            <p className="text-sm text-muted-foreground">Start your first security scan to see results here</p>
          </div>
        )}

        <div className="space-y-3">
          {history.map((scan) => (
            <div
              key={scan.id}
              className="border border-border/50 rounded-lg p-4 bg-muted/20 hover:bg-muted/30 transition-all hover:border-primary/30 backdrop-blur-sm"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0 space-y-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="font-semibold truncate font-mono text-sm">{scan.target_url}</h3>
                    {getTotalVulnerabilities(scan) > 0 && (
                      <Badge variant="destructive" className="text-xs">
                        {getTotalVulnerabilities(scan)} vulnerabilities
                      </Badge>
                    )}
                    {getTotalVulnerabilities(scan) === 0 && (
                      <Badge variant="outline" className="text-xs border-success text-success">
                        Secure
                      </Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                    <div className="flex items-center gap-1">
                      <Clock className="h-3 w-3" />
                      {formatDate(scan.scan_time)}
                    </div>
                    <Badge variant="secondary" className="text-xs bg-muted/50">
                      {scan.summary.total_pages_scanned} pages
                    </Badge>
                    <Badge variant="secondary" className="text-xs bg-muted/50">
                      {scan.summary.total_forms_found} forms
                    </Badge>
                    {scan.summary.missing_security_headers > 0 && (
                      <Badge variant="outline" className="text-xs border-warning text-warning">
                        {scan.summary.missing_security_headers} headers missing
                      </Badge>
                    )}
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button
                    onClick={() => onViewScan(scan.id)}
                    variant="outline"
                    size="sm"
                    className="gap-2 border-border/50 hover:border-primary/50 hover:bg-primary/10"
                  >
                    <Eye className="h-4 w-4" />
                    View
                  </Button>
                  <Button
                    onClick={() => deleteScan(scan.id)}
                    variant="outline"
                    size="sm"
                    className="text-destructive hover:text-destructive hover:bg-destructive/10 border-border/50 hover:border-destructive/50"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
