/**
 * Client-Side OCR Engine powered by Tesseract.js WebAssembly.
 * Extracts text from uploaded screenshots directly in the browser with 0 external C++ dependencies.
 */

class OCREngine {
    constructor() {
        this.isProcessing = false;
    }

    async extractTextFromImage(imageFile, onProgress = null) {
        if (!window.Tesseract) {
            throw new Error("Tesseract.js library not loaded from CDN.");
        }

        this.isProcessing = true;

        try {
            const { data } = await Tesseract.recognize(
                imageFile,
                'eng',
                {
                    logger: m => {
                        if (onProgress && m.status === 'recognizing text') {
                            const pct = Math.round((m.progress || 0) * 100);
                            onProgress(pct, m.status);
                        }
                    }
                }
            );

            this.isProcessing = false;
            return {
                text: data.text ? data.text.trim() : "",
                confidence: data.confidence,
                words: data.words ? data.words.length : 0
            };
        } catch (err) {
            this.isProcessing = false;
            console.error("OCR extraction failed:", err);
            throw err;
        }
    }
}

window.ocrEngine = new OCREngine();
