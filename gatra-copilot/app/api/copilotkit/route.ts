import {
  CopilotRuntime,
  ExperimentalEmptyAdapter,
  copilotRuntimeNextJSAppRouterEndpoint,
} from "@copilotkit/runtime";
import { LangGraphHttpAgent } from "@copilotkit/runtime/langgraph";

const agentUrl = process.env.LANGGRAPH_AGENT_URL || "http://localhost:8123";

const gatra_soc = new LangGraphHttpAgent({
  url: agentUrl,
});

const runtime = new CopilotRuntime({
  defaultAgent: gatra_soc,
});

const { handleRequest } = copilotRuntimeNextJSAppRouterEndpoint({
  runtime,
  serviceAdapter: new ExperimentalEmptyAdapter(),
  endpoint: "/api/copilotkit",
});

export const POST = handleRequest;
