
import { GoogleGenAI } from "@google/genai";
import { AnimationStep, ExploitType } from '../types';

let ai: GoogleGenAI | null = null;

// Initialize GoogleGenAI client with API key from environment
if (process.env.API_KEY) {
  ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
}

export const getGeminiExplanation = async (
  exploitType: ExploitType,
  currentStep: AnimationStep
): Promise<string> => {
  if (!ai) {
    return "Gemini API Key is missing. Please check your environment configuration.";
  }

  const prompt = `
    You are a cybersecurity expert explaining binary exploitation to a student.
    
    Current Topic: ${exploitType === ExploitType.STACK ? "Stack Buffer Overflow" : "Heap Overflow"}
    Current Step: ${currentStep.title}
    Description: ${currentStep.description}
    
    Please provide a concise, easy-to-understand explanation (max 3 sentences) of what is happening in the computer's memory at this exact moment and why it is dangerous.
    If it is the overflow step, explain specifically what data is being overwritten.
  `;

  try {
    // Corrected to use 'gemini-3-flash-preview' for text-based educational tasks
    const response = await ai.models.generateContent({
      model: 'gemini-3-flash-preview',
      contents: prompt,
      config: {
        systemInstruction: "You are a helpful and precise computer science tutor.",
      }
    });

    // Directly access the .text property from GenerateContentResponse
    return response.text || "No explanation available.";
  } catch (error) {
    console.error("Gemini API Error:", error);
    return "Failed to retrieve explanation from Gemini. Please try again.";
  }
};
