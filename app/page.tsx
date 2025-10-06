"use client"

import { useState, Suspense } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Progress } from "@/components/ui/progress"
import {
  Shield,
  Search,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Globe,
  FileText,
  Lock,
  Activity,
  TrendingUp,
  Zap,
  Database,
  Code,
  Terminal,
  ShieldAlert,
  Scan,
  Radio,
} from "lucide-react"
import { ScanHistory } from "@/components/scan-history"
import { Scanner3D } from "@/components/scanner-3d"
import { RadarScanner } from "@/components/radar-scanner"

interface ScanResult {
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
  crawl_results: any
  header_results: any
  vulnerability_results: any[]
}

export default function SecurityScanner() {
  const [url, setUrl] = useState("")
  const [loading, setLoading] = useState(false)
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState("")

  const handleScan = async () => {
    if (!url) {
      setError("Please enter a URL to scan")
      return
    }

    setLoading(true)
    setError("")
    setScanResult(null)

    try {
      const response = await fetch("http://localhost:5000/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url }),
      })

      if (!response.ok) {
        throw new Error("Scan failed")
      }

      const data = await response.json()
      setScanResult(data)
    } catch (err) {
      setError("Failed to scan website. Make sure the Flask server is running on port 5000.")
    } finally {
      setLoading(false)
    }
  }

  const handleViewScan = async (scanId: number) => {
    try {
      const response = await fetch(`http://localhost:5000/api/history/${scanId}`)
      if (!response.ok) throw new Error("Failed to load scan")

      const data = await response.json()
      setScanResult(data)
      setUrl(data.target_url)
    } catch (err) {
      setError("Failed to load scan from history")
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "destructive"
      case "high":
        return "destructive"
      case "medium":
        return "default"
      case "low":
        return "secondary"
      default:
        return "secondary"
    }
  }

  const getTotalVulnerabilities = () => {
    if (!scanResult) return 0
    return scanResult.summary.sql_injection_vulnerabilities + scanResult.summary.xss_vulnerabilities
  }

  const getSecurityScore = () => {
    if (!scanResult) return 0
    const total = getTotalVulnerabilities() + scanResult.summary.missing_security_headers
    if (total === 0) return 100
    if (total <= 2) return 85
    if (total <= 5) return 65
    if (total <= 10) return 40
    return 20
  }

  return (
    <div className="min-h-screen bg-background cyber-grid">
      <div className="border-b border-primary/20 glass-card sticky top-0 z-50 shadow-2xl">
        <div className="container mx-auto px-6 py-4 max-w-7xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="relative">
                <div className="absolute inset-0 bg-primary blur-xl animate-pulse" />
                <Shield className="h-10 w-10 text-primary relative z-10 drop-shadow-[0_0_10px_rgba(96,165,250,0.8)]" />
              </div>
              <div>
                <h1 className="text-3xl font-bold gradient-text tracking-tight">SECUREWEB</h1>
                <p className="text-xs text-muted-foreground font-mono tracking-wider">
                  ADVANCED THREAT DETECTION SYSTEM
                </p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <Badge variant="outline" className="gap-2 border-success/50 text-success glow-text font-mono">
                <Radio className="h-3 w-3 animate-pulse" />
                ONLINE
              </Badge>
            </div>
          </div>
        </div>
      </div>

      <div className="container mx-auto px-6 py-8 max-w-7xl">
        <div className="mb-8 relative">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* 3D Scanner */}
            <Card className="border-primary/30 glass-card shadow-2xl overflow-hidden neon-border relative">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-mono uppercase tracking-wider flex items-center gap-2 glow-text">
                  <Activity className="h-4 w-4 animate-pulse" />
                  3D Threat Scanner
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <div className="h-[300px] relative">
                  <Suspense
                    fallback={
                      <div className="w-full h-full flex items-center justify-center bg-gradient-to-b from-background to-primary/5">
                        <Activity className="h-8 w-8 animate-spin text-primary glow-text" />
                      </div>
                    }
                  >
                    <Scanner3D />
                  </Suspense>
                  <div className="scan-line" />
                </div>
              </CardContent>
            </Card>

            {/* Radar Sweep Visualization */}
            <Card className="border-accent/30 glass-card shadow-2xl overflow-hidden neon-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-mono uppercase tracking-wider flex items-center gap-2 glow-text">
                  <Radio className="h-4 w-4 animate-pulse" />
                  Radar Sweep
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                <div className="h-[200px] flex items-center justify-center bg-gradient-to-b from-background to-accent/5">
                  <RadarScanner />
                </div>
              </CardContent>
            </Card>

            {/* Scan Input */}
            <Card className="border-primary/30 glass-card shadow-2xl neon-border">
              <CardHeader>
                <div className="flex items-center gap-2">
                  <Scan className="h-5 w-5 text-primary glow-text" />
                  <CardTitle className="font-mono uppercase tracking-wider">Initialize Scan</CardTitle>
                </div>
                <CardDescription className="font-mono text-xs">
                  Deploy comprehensive vulnerability assessment protocols
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-3">
                  <div className="relative flex-1">
                    <Globe className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-primary glow-text" />
                    <Input
                      placeholder="https://target-domain.com"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                      className="pl-10 h-12 glass-card border-primary/30 focus:border-primary font-mono text-sm glow-box"
                      disabled={loading}
                      onKeyDown={(e) => e.key === "Enter" && handleScan()}
                    />
                  </div>
                  <Button
                    onClick={handleScan}
                    disabled={loading}
                    className="h-12 px-8 gap-2 bg-primary hover:bg-primary/90 glow-box font-mono uppercase tracking-wider"
                    size="lg"
                  >
                    {loading ? (
                      <>
                        <Activity className="h-4 w-4 animate-spin" />
                        Scanning
                      </>
                    ) : (
                      <>
                        <Search className="h-4 w-4" />
                        Deploy
                      </>
                    )}
                  </Button>
                </div>
                {error && (
                  <Alert variant="destructive" className="border-destructive/50 glass-card">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertDescription className="font-mono text-xs">{error}</AlertDescription>
                  </Alert>
                )}
                {loading && (
                  <div className="space-y-3 glass-card p-4 rounded-lg border border-primary/30 neon-border">
                    <div className="flex items-center justify-between text-sm font-mono">
                      <span className="text-muted-foreground">SCANNING TARGET...</span>
                      <span className="text-primary glow-text">PROCESSING</span>
                    </div>
                    <Progress value={33} className="h-2 bg-muted glow-box" />
                    <div className="text-xs text-muted-foreground font-mono space-y-1">
                      <div className="flex items-center gap-2">
                        <div className="h-1 w-1 rounded-full bg-primary animate-pulse glow-text" />
                        Crawling web pages...
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="h-1 w-1 rounded-full bg-accent animate-pulse glow-text" />
                        Testing injection vectors...
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="h-1 w-1 rounded-full bg-secondary animate-pulse glow-text" />
                        Analyzing security headers...
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>

        <div className="mb-8">
          <ScanHistory onViewScan={handleViewScan} />
        </div>

        {scanResult && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
              <Card className="border-primary/30 glass-card metric-card shadow-2xl glow-box">
                <CardHeader className="pb-3">
                  <CardTitle className="text-xs font-mono uppercase tracking-wider flex items-center gap-2 text-muted-foreground">
                    <Shield className="h-4 w-4" />
                    Security Score
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-6xl font-bold gradient-text">{getSecurityScore()}</div>
                  <p className="text-xs text-muted-foreground mt-2 font-mono uppercase">
                    {getSecurityScore() >= 80 ? "Excellent" : getSecurityScore() >= 60 ? "Good" : "Critical"}
                  </p>
                  <Progress value={getSecurityScore()} className="mt-3 h-2 bg-muted glow-box" />
                </CardContent>
              </Card>

              <Card className="border-accent/30 glass-card metric-card shadow-2xl">
                <CardHeader className="pb-3">
                  <CardTitle className="text-xs font-mono uppercase tracking-wider flex items-center gap-2 text-muted-foreground">
                    <Globe className="h-4 w-4" />
                    Coverage
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-5xl font-bold text-accent glow-text">
                    {scanResult.summary.total_pages_scanned}
                  </div>
                  <p className="text-xs text-muted-foreground mt-1 font-mono">
                    {scanResult.summary.total_forms_found} forms analyzed
                  </p>
                  <div className="flex items-center gap-1 mt-3 text-success">
                    <TrendingUp className="h-3 w-3" />
                    <span className="text-xs font-mono uppercase">Complete</span>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-destructive/30 glass-card metric-card shadow-2xl">
                <CardHeader className="pb-3">
                  <CardTitle className="text-xs font-mono uppercase tracking-wider flex items-center gap-2 text-muted-foreground">
                    <ShieldAlert className="h-4 w-4" />
                    Threats
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div
                    className={`text-5xl font-bold ${getTotalVulnerabilities() > 0 ? "text-destructive glow-text" : "text-success glow-text"}`}
                  >
                    {getTotalVulnerabilities()}
                  </div>
                  <p className="text-xs text-muted-foreground mt-1 font-mono">
                    {scanResult.summary.sql_injection_vulnerabilities} SQL · {scanResult.summary.xss_vulnerabilities}{" "}
                    XSS
                  </p>
                  {getTotalVulnerabilities() > 0 && (
                    <Badge variant="destructive" className="mt-3 text-xs font-mono uppercase">
                      Action Required
                    </Badge>
                  )}
                </CardContent>
              </Card>

              <Card className="border-warning/30 glass-card metric-card shadow-2xl">
                <CardHeader className="pb-3">
                  <CardTitle className="text-xs font-mono uppercase tracking-wider flex items-center gap-2 text-muted-foreground">
                    <Lock className="h-4 w-4" />
                    Headers
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div
                    className={`text-5xl font-bold ${scanResult.summary.missing_security_headers > 0 ? "text-warning glow-text" : "text-success glow-text"}`}
                  >
                    {scanResult.summary.missing_security_headers}
                  </div>
                  <p className="text-xs text-muted-foreground mt-1 font-mono">missing headers</p>
                  {scanResult.summary.missing_security_headers > 0 && (
                    <Badge variant="outline" className="mt-3 text-xs border-warning text-warning font-mono uppercase">
                      Review
                    </Badge>
                  )}
                </CardContent>
              </Card>
            </div>

            <Tabs defaultValue="vulnerabilities" className="w-full">
              <TabsList className="grid w-full grid-cols-3 glass-card border border-primary/30 h-12">
                <TabsTrigger
                  value="vulnerabilities"
                  className="gap-2 data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-mono uppercase text-xs"
                >
                  <Zap className="h-4 w-4" />
                  Threats
                </TabsTrigger>
                <TabsTrigger
                  value="headers"
                  className="gap-2 data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-mono uppercase text-xs"
                >
                  <Lock className="h-4 w-4" />
                  Headers
                </TabsTrigger>
                <TabsTrigger
                  value="crawl"
                  className="gap-2 data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-mono uppercase text-xs"
                >
                  <Database className="h-4 w-4" />
                  Data
                </TabsTrigger>
              </TabsList>

              <TabsContent value="vulnerabilities" className="space-y-4 mt-6">
                <Card className="border-primary/30 glass-card shadow-2xl">
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="flex items-center gap-2 font-mono uppercase tracking-wider">
                          <AlertTriangle className="h-5 w-5 text-destructive glow-text" />
                          Detected Vulnerabilities
                        </CardTitle>
                        <CardDescription className="mt-1 font-mono text-xs">
                          Critical security issues requiring immediate attention
                        </CardDescription>
                      </div>
                      {getTotalVulnerabilities() > 0 && (
                        <Badge variant="destructive" className="text-lg px-4 py-1 font-mono glow-box">
                          {getTotalVulnerabilities()}
                        </Badge>
                      )}
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {scanResult.vulnerability_results.map((result, idx) => (
                        <div key={idx} className="space-y-3">
                          {result.sql_injection.map((vuln: any, vIdx: number) => (
                            <div
                              key={`sql-${vIdx}`}
                              className="border border-destructive/30 rounded-lg p-4 glass-card hover:border-destructive/50 transition-all neon-border"
                            >
                              <div className="flex items-start gap-3">
                                <div className="mt-1">
                                  <AlertTriangle className="h-5 w-5 text-destructive glow-text" />
                                </div>
                                <div className="flex-1 space-y-3">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <Badge variant="destructive" className="font-mono uppercase">
                                      {vuln.severity}
                                    </Badge>
                                    <Badge variant="outline" className="font-mono">
                                      {vuln.type}
                                    </Badge>
                                    <Badge variant="secondary" className="text-xs font-mono">
                                      {vuln.method}
                                    </Badge>
                                  </div>
                                  <div className="space-y-2 text-sm">
                                    <div className="flex items-start gap-2">
                                      <Code className="h-4 w-4 mt-0.5 text-muted-foreground flex-shrink-0" />
                                      <div className="flex-1">
                                        <p className="text-xs text-muted-foreground mb-1 font-mono uppercase">
                                          Target URL
                                        </p>
                                        <code className="text-xs break-all font-mono">{vuln.url}</code>
                                      </div>
                                    </div>
                                    <div className="flex items-start gap-2">
                                      <Terminal className="h-4 w-4 mt-0.5 text-muted-foreground flex-shrink-0" />
                                      <div className="flex-1">
                                        <p className="text-xs text-muted-foreground mb-1 font-mono uppercase">
                                          Payload
                                        </p>
                                        <code className="text-xs glass-card px-2 py-1 rounded block break-all font-mono border border-primary/20">
                                          {vuln.payload}
                                        </code>
                                      </div>
                                    </div>
                                    <div className="flex items-start gap-2">
                                      <FileText className="h-4 w-4 mt-0.5 text-muted-foreground flex-shrink-0" />
                                      <div className="flex-1">
                                        <p className="text-xs text-muted-foreground mb-1 font-mono uppercase">
                                          Evidence
                                        </p>
                                        <p className="text-xs font-mono">{vuln.evidence}</p>
                                      </div>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </div>
                          ))}
                          {result.xss.map((vuln: any, vIdx: number) => (
                            <div
                              key={`xss-${vIdx}`}
                              className="border border-destructive/30 rounded-lg p-4 glass-card hover:border-destructive/50 transition-all neon-border"
                            >
                              <div className="flex items-start gap-3">
                                <div className="mt-1">
                                  <AlertTriangle className="h-5 w-5 text-destructive glow-text" />
                                </div>
                                <div className="flex-1 space-y-3">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <Badge variant="destructive" className="font-mono uppercase">
                                      {vuln.severity}
                                    </Badge>
                                    <Badge variant="outline" className="font-mono">
                                      {vuln.type}
                                    </Badge>
                                    <Badge variant="secondary" className="text-xs font-mono">
                                      {vuln.method}
                                    </Badge>
                                  </div>
                                  <div className="space-y-2 text-sm">
                                    <div className="flex items-start gap-2">
                                      <Code className="h-4 w-4 mt-0.5 text-muted-foreground flex-shrink-0" />
                                      <div className="flex-1">
                                        <p className="text-xs text-muted-foreground mb-1 font-mono uppercase">
                                          Target URL
                                        </p>
                                        <code className="text-xs break-all font-mono">{vuln.url}</code>
                                      </div>
                                    </div>
                                    <div className="flex items-start gap-2">
                                      <Terminal className="h-4 w-4 mt-0.5 text-muted-foreground flex-shrink-0" />
                                      <div className="flex-1">
                                        <p className="text-xs text-muted-foreground mb-1 font-mono uppercase">
                                          Payload
                                        </p>
                                        <code className="text-xs glass-card px-2 py-1 rounded block break-all font-mono border border-primary/20">
                                          {vuln.payload}
                                        </code>
                                      </div>
                                    </div>
                                    <div className="flex items-start gap-2">
                                      <FileText className="h-4 w-4 mt-0.5 text-muted-foreground flex-shrink-0" />
                                      <div className="flex-1">
                                        <p className="text-xs text-muted-foreground mb-1 font-mono uppercase">
                                          Evidence
                                        </p>
                                        <p className="text-xs font-mono">{vuln.evidence}</p>
                                      </div>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      ))}
                      {getTotalVulnerabilities() === 0 && (
                        <div className="text-center py-12">
                          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full glass-card mb-4 border border-success/30 glow-box">
                            <CheckCircle className="h-8 w-8 text-success glow-text" />
                          </div>
                          <h3 className="text-lg font-semibold mb-2 font-mono uppercase">No Threats Detected</h3>
                          <p className="text-sm text-muted-foreground font-mono">
                            All tested forms appear to be secure against SQL Injection and XSS attacks.
                          </p>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="headers" className="space-y-4 mt-6">
                <Card className="border-primary/30 glass-card shadow-2xl">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 font-mono uppercase tracking-wider">
                      <Lock className="h-5 w-5 glow-text" />
                      Security Headers Analysis
                    </CardTitle>
                    <CardDescription className="font-mono text-xs">
                      HTTP security headers configuration assessment
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    {scanResult.header_results.missing_headers.length > 0 && (
                      <div>
                        <div className="flex items-center gap-2 mb-4">
                          <XCircle className="h-5 w-5 text-destructive glow-text" />
                          <h3 className="font-semibold text-lg font-mono uppercase">Missing Headers</h3>
                          <Badge variant="destructive" className="font-mono">
                            {scanResult.header_results.missing_headers.length}
                          </Badge>
                        </div>
                        <div className="grid gap-3">
                          {scanResult.header_results.missing_headers.map((header: any, idx: number) => (
                            <div
                              key={idx}
                              className="border border-border/50 rounded-lg p-4 glass-card hover:border-destructive/30 transition-all"
                            >
                              <div className="flex items-center gap-2 mb-2">
                                <code className="font-mono text-sm font-semibold">{header.name}</code>
                                <Badge
                                  variant={getSeverityColor(header.severity)}
                                  className="font-mono text-xs uppercase"
                                >
                                  {header.severity}
                                </Badge>
                              </div>
                              <p className="text-sm text-muted-foreground font-mono">{header.description}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {scanResult.header_results.present_headers.length > 0 && (
                      <div>
                        <div className="flex items-center gap-2 mb-4">
                          <CheckCircle className="h-5 w-5 text-success glow-text" />
                          <h3 className="font-semibold text-lg font-mono uppercase">Present Headers</h3>
                          <Badge variant="outline" className="border-success text-success font-mono">
                            {scanResult.header_results.present_headers.length}
                          </Badge>
                        </div>
                        <div className="grid gap-3">
                          {scanResult.header_results.present_headers.map((header: any, idx: number) => (
                            <div
                              key={idx}
                              className="border border-success/20 rounded-lg p-4 glass-card hover:border-success/40 transition-all"
                            >
                              <div className="flex items-center gap-2 mb-2">
                                <CheckCircle className="h-4 w-4 text-success" />
                                <code className="font-mono text-sm font-semibold">{header.name}</code>
                              </div>
                              <p className="text-xs text-muted-foreground mb-2 font-mono">{header.description}</p>
                              <code className="text-xs glass-card px-3 py-2 rounded block break-all border border-success/20 font-mono">
                                {header.value}
                              </code>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </TabsContent>

              <TabsContent value="crawl" className="space-y-4 mt-6">
                <Card className="border-primary/30 glass-card shadow-2xl">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 font-mono uppercase tracking-wider">
                      <Database className="h-5 w-5 glow-text" />
                      Crawl Results
                    </CardTitle>
                    <CardDescription className="font-mono text-xs">
                      Discovered pages and forms during reconnaissance
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-6">
                      <div>
                        <div className="flex items-center gap-2 mb-4">
                          <FileText className="h-5 w-5 text-primary glow-text" />
                          <h3 className="font-semibold text-lg font-mono uppercase">Discovered Pages</h3>
                          <Badge variant="outline" className="font-mono">
                            {scanResult.crawl_results.total_pages}
                          </Badge>
                        </div>
                        <div className="space-y-2 max-h-96 overflow-y-auto pr-2">
                          {scanResult.crawl_results.pages.map((page: any, idx: number) => (
                            <div
                              key={idx}
                              className="flex items-center justify-between gap-4 border border-border/50 rounded-lg p-3 glass-card hover:border-primary/30 transition-all"
                            >
                              <code className="font-mono text-xs truncate flex-1">{page.url}</code>
                              <Badge
                                variant={page.status_code === 200 ? "outline" : "secondary"}
                                className="font-mono text-xs"
                              >
                                {page.status_code}
                              </Badge>
                            </div>
                          ))}
                        </div>
                      </div>

                      {scanResult.crawl_results.total_forms > 0 && (
                        <div>
                          <div className="flex items-center gap-2 mb-4">
                            <Code className="h-5 w-5 text-primary glow-text" />
                            <h3 className="font-semibold text-lg font-mono uppercase">Forms Found</h3>
                            <Badge variant="outline" className="font-mono">
                              {scanResult.crawl_results.total_forms}
                            </Badge>
                          </div>
                          <div className="space-y-3 max-h-96 overflow-y-auto pr-2">
                            {scanResult.crawl_results.forms.map((form: any, idx: number) => (
                              <div
                                key={idx}
                                className="border border-border/50 rounded-lg p-4 glass-card hover:border-primary/30 transition-all"
                              >
                                <div className="flex items-center gap-2 mb-3">
                                  <Badge variant="outline" className="font-mono uppercase">
                                    {form.method}
                                  </Badge>
                                  <code className="font-mono text-xs truncate flex-1">{form.action}</code>
                                </div>
                                <div className="flex flex-wrap gap-2">
                                  {form.inputs.map((inp: any, iIdx: number) => (
                                    <Badge key={iIdx} variant="secondary" className="text-xs font-mono">
                                      {inp.name || inp.type}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        )}
      </div>
    </div>
  )
}
