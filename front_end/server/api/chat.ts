import { StreamingTextResponse, streamText } from "ai";
import { ollama } from 'ollama-ai-provider';

export default defineLazyEventHandler(async () => {
    
    return defineEventHandler(async (event: any) => {
      const { messages } = await readBody(event);
  
      const result = await streamText({
        model: ollama('qwen2:7b-instruct'),
        messages,
      });
  
      return new StreamingTextResponse(result.toAIStream());
    });
  });