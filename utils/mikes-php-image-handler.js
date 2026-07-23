"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VampireImageClient = void 0;
class VampireImageClient {
    apiKey;
    baseUrl;
    timeoutMs;
    maxRetries;
    constructor(options) {
        this.apiKey = options.apiKey;
        this.baseUrl = options.baseUrl.replace(/\/$/, '');
        this.timeoutMs = options.timeoutMs || 30000;
        this.maxRetries = options.maxRetries ?? 3;
    }
    getHeaders(isFormData = false) {
        const headers = {
            'Authorization': `Bearer ${this.apiKey}`
        };
        if (!isFormData) {
            headers['Content-Type'] = 'application/json';
        }
        return headers;
    }
    /**
     * Internal fetch wrapper with timeout and retry logic
     */
    async fetchWithRetry(url, options, retries) {
        let lastError = new Error('Request failed');
        for (let attempt = 0; attempt <= retries; attempt++) {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);
            try {
                const res = await fetch(url, { ...options, signal: controller.signal });
                clearTimeout(timeoutId);
                if (res.ok || (res.status >= 400 && res.status < 500)) {
                    // Successful response or client error (no need to retry 4xx errors usually)
                    return res;
                }
                throw new Error(`Server responded with status ${res.status}`);
            }
            catch (err) {
                clearTimeout(timeoutId);
                lastError = err instanceof Error ? err : new Error(String(err));
                // If it's an abort error (timeout), or network error, we retry.
                if (attempt < retries) {
                    const delay = Math.pow(2, attempt) * 1000; // Exponential backoff: 1s, 2s, 4s...
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
            }
        }
        throw lastError;
    }
    /**
     * Upload an image to the PHP server.
     * @param file A standard File, Blob, Buffer, or Uint8Array.
     * @param filename Optional filename (required if passing a Buffer/Uint8Array)
     */
    async uploadImage(file, filename) {
        const formData = new FormData();
        let blobToUpload;
        if (file instanceof Uint8Array) {
            blobToUpload = new Blob([file]);
        }
        else {
            blobToUpload = file;
        }
        if (filename) {
            formData.append('image', blobToUpload, filename);
        }
        else {
            formData.append('image', blobToUpload);
        }
        try {
            const response = await this.fetchWithRetry(`${this.baseUrl}/upload`, {
                method: 'POST',
                headers: this.getHeaders(true),
                body: formData
            }, this.maxRetries);
            if (!response.ok) {
                const text = await response.text();
                throw new Error(`Upload failed with status ${response.status}: ${text}`);
            }
            const data = await response.json();
            return {
                success: data.success || false,
                url: data.url,
                filename: data.filename,
                error: data.error
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : String(error)
            };
        }
    }
    /**
     * Upload a Base64 encoded image string to the PHP server.
     * @param base64String The base64 string (can include the data URI prefix like "data:image/png;base64,...")
     * @param filename The filename to save it as
     */
    async uploadBase64(base64String, filename) {
        // Strip data prefix if present
        const base64Data = base64String.replace(/^data:image\/\w+;base64,/, '');
        try {
            // Convert base64 to Uint8Array (works in Browser and Node)
            const binaryString = atob(base64Data);
            const len = binaryString.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            return await this.uploadImage(bytes, filename);
        }
        catch (error) {
            return {
                success: false,
                error: `Failed to process base64 string: ${error instanceof Error ? error.message : String(error)}`
            };
        }
    }
    /**
     * Delete an image by its filename
     * @param filename The exact filename (e.g., 'img_123.jpg')
     */
    async deleteImage(filename) {
        try {
            const response = await this.fetchWithRetry(`${this.baseUrl}/delete`, {
                method: 'DELETE',
                headers: this.getHeaders(),
                body: JSON.stringify({ filename })
            }, this.maxRetries);
            if (!response.ok) {
                const text = await response.text();
                throw new Error(`Delete failed with status ${response.status}: ${text}`);
            }
            const data = await response.json();
            return {
                success: data.success || false,
                message: data.message,
                error: data.error
            };
        }
        catch (error) {
            return {
                success: false,
                error: error instanceof Error ? error.message : String(error)
            };
        }
    }
}
exports.VampireImageClient = VampireImageClient;
