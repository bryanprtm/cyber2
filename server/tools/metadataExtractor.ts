import { exiftool } from 'exiftool-vendored';
import { fileTypeFromBuffer } from 'file-type';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { createHash } from 'crypto';

const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);
const unlink = promisify(fs.unlink);

export interface MetadataExtractorOptions {
  fileBuffer: Buffer;
  fileName?: string;
  extractLocation?: boolean;
  fileType?: string;
}

export interface ExifData {
  [key: string]: any;
}

export interface MetadataResult {
  fileName: string;
  fileSize: number;
  fileType: string;
  mimeType: string;
  hash: {
    md5: string;
    sha1: string;
  };
  created?: Date;
  modified?: Date;
  metadata: ExifData;
  exif?: {
    make?: string;
    model?: string;
    software?: string;
    dateTime?: string;
    gps?: {
      latitude?: number;
      longitude?: number;
      altitude?: number;
    };
  };
  sanitized: boolean;
  categories: string[];
}

/**
 * Extract metadata from a file
 * @param options Metadata extractor options
 * @returns Metadata information from the file
 */
export async function extractMetadata(options: MetadataExtractorOptions): Promise<MetadataResult> {
  let tempFilePath: string | null = null;
  
  try {
    const fileBuffer = options.fileBuffer;
    const fileName = options.fileName || 'unknown_file';
    
    // Calculate hashes
    const md5Hash = createHash('md5').update(fileBuffer).digest('hex');
    const sha1Hash = createHash('sha1').update(fileBuffer).digest('hex');
    
    // Detect file type
    const fileTypeResult = await fileTypeFromBuffer(fileBuffer);
    const mimeType = fileTypeResult?.mime || 'application/octet-stream';
    const fileType = options.fileType || fileTypeResult?.ext || 'unknown';
    
    // Create a temporary file for ExifTool to analyze
    const tempDir = os.tmpdir();
    tempFilePath = path.join(tempDir, `${md5Hash}.${fileType}`);
    await writeFile(tempFilePath, fileBuffer);
    
    // Extract metadata with ExifTool
    const exifData = await exiftool.read(tempFilePath);
    
    // Categorize the file based on its type
    const categories = categorizeFile(fileType, mimeType);
    
    // Determine if sensitive data was removed or sanitized
    const sanitized = !options.extractLocation && containsLocationData(exifData);
    
    // Format EXIF data specifically for common file types
    let exifSpecific = undefined;
    
    // For images, extract camera and GPS info if available and requested
    if (['jpg', 'jpeg', 'png', 'tiff', 'heic'].includes(fileType.toLowerCase())) {
      exifSpecific = {
        make: exifData.Make,
        model: exifData.Model,
        software: exifData.Software,
        dateTime: exifData.DateTimeOriginal || exifData.CreateDate
      };
      
      // Include GPS data if requested and available
      if (options.extractLocation && hasGpsData(exifData)) {
        exifSpecific.gps = {
          latitude: exifData.GPSLatitude,
          longitude: exifData.GPSLongitude,
          altitude: exifData.GPSAltitude
        };
      }
    }
    
    // Get dates
    const createdDate = exifData.CreateDate || exifData.DateTimeOriginal 
      ? new Date(exifData.CreateDate || exifData.DateTimeOriginal) 
      : undefined;
      
    const modifiedDate = exifData.ModifyDate 
      ? new Date(exifData.ModifyDate) 
      : undefined;
    
    // Create the result object
    const result: MetadataResult = {
      fileName,
      fileSize: fileBuffer.length,
      fileType,
      mimeType,
      hash: {
        md5: md5Hash,
        sha1: sha1Hash
      },
      created: createdDate,
      modified: modifiedDate,
      metadata: exifData,
      exif: exifSpecific,
      sanitized,
      categories
    };
    
    return result;
  } catch (error) {
    console.error('Metadata extraction error:', error);
    throw new Error(`Metadata extraction failed: ${(error as Error).message}`);
  } finally {
    // Clean up temporary file
    if (tempFilePath) {
      try {
        await unlink(tempFilePath);
      } catch (err) {
        console.error('Error removing temporary file:', err);
      }
    }
  }
}

/**
 * Check if the metadata contains GPS/location information
 */
function hasGpsData(metadata: ExifData): boolean {
  return !!(
    metadata.GPSLatitude !== undefined && 
    metadata.GPSLongitude !== undefined
  );
}

/**
 * Check if the metadata contains any location data
 */
function containsLocationData(metadata: ExifData): boolean {
  const locationFields = [
    'GPSLatitude', 'GPSLongitude', 'GPSAltitude',
    'GPSDateStamp', 'GPSTimeStamp', 'GPSPosition',
    'Location', 'City', 'State', 'Country',
    'CountryCode'
  ];
  
  return locationFields.some(field => metadata[field] !== undefined);
}

/**
 * Categorize file based on its type and MIME type
 */
function categorizeFile(fileType: string, mimeType: string): string[] {
  const categories: string[] = [];
  const fileTypeLower = fileType.toLowerCase();
  
  // Image files
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff', 'tif', 'svg', 'heic'].includes(fileTypeLower) || 
      mimeType.startsWith('image/')) {
    categories.push('Image');
  }
  
  // Document files
  if (['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'txt', 'rtf'].includes(fileTypeLower) || 
      mimeType.includes('document') || 
      mimeType.includes('spreadsheet') || 
      mimeType.includes('presentation')) {
    categories.push('Document');
  }
  
  // Audio files
  if (['mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac'].includes(fileTypeLower) || 
      mimeType.startsWith('audio/')) {
    categories.push('Audio');
  }
  
  // Video files
  if (['mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm'].includes(fileTypeLower) || 
      mimeType.startsWith('video/')) {
    categories.push('Video');
  }
  
  // Archive files
  if (['zip', 'rar', '7z', 'tar', 'gz', 'bz2'].includes(fileTypeLower) || 
      mimeType.includes('archive') ||
      mimeType.includes('compressed')) {
    categories.push('Archive');
  }
  
  // Font files
  if (['ttf', 'otf', 'woff', 'woff2', 'eot'].includes(fileTypeLower) || 
      mimeType.includes('font')) {
    categories.push('Font');
  }
  
  // Executable files
  if (['exe', 'dll', 'msi', 'app', 'dmg', 'sh', 'bat', 'com'].includes(fileTypeLower) ||
      mimeType.includes('executable') ||
      mimeType.includes('application/x-msdownload')) {
    categories.push('Executable');
  }
  
  // If no category was assigned, use a generic one
  if (categories.length === 0) {
    categories.push('Other');
  }
  
  return categories;
}