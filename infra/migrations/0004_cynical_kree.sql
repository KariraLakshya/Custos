CREATE TABLE "agent_policies" (
	"agent_did" text NOT NULL,
	"tool" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "agent_policies_agent_did_tool_pk" PRIMARY KEY("agent_did","tool")
);
--> statement-breakpoint
CREATE TABLE "audit_records" (
	"id" serial PRIMARY KEY NOT NULL,
	"agent_did" text NOT NULL,
	"tool" text NOT NULL,
	"action" text NOT NULL,
	"data_categories" jsonb NOT NULL,
	"policy_rule" text NOT NULL,
	"decision" text NOT NULL,
	"reason" text,
	"recorded_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
