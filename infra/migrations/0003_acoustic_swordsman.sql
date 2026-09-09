CREATE TABLE "status_list_entries" (
	"agent_did" text PRIMARY KEY NOT NULL,
	"agent_id" uuid NOT NULL,
	"status_list_index" serial NOT NULL,
	"revoked_at" timestamp with time zone,
	"reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "status_list_entries_agent_id_unique" UNIQUE("agent_id"),
	CONSTRAINT "status_list_entries_status_list_index_unique" UNIQUE("status_list_index")
);
