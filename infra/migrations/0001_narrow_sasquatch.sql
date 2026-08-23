CREATE TABLE "agents" (
	"id" uuid PRIMARY KEY NOT NULL,
	"did" text NOT NULL,
	"key_id" text NOT NULL,
	"did_document" jsonb NOT NULL,
	"credential" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "agents_did_unique" UNIQUE("did")
);
