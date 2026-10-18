CREATE TABLE "external_revoked_indexes" (
	"status_list_index" integer PRIMARY KEY NOT NULL,
	"first_seen_in_list_at" timestamp with time zone NOT NULL,
	"merged_at" timestamp with time zone DEFAULT now() NOT NULL
);
