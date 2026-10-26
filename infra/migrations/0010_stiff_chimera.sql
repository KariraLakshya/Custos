CREATE TABLE "audit_seals" (
	"seq" integer PRIMARY KEY NOT NULL,
	"head_hash" text NOT NULL,
	"seal" text NOT NULL,
	"sealed_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
ALTER TABLE "audit_records" ADD COLUMN "reported_by_kind" text;--> statement-breakpoint
ALTER TABLE "audit_records" ADD COLUMN "reported_by_id" text;--> statement-breakpoint
ALTER TABLE "audit_records" ADD COLUMN "reported_by_name" text;--> statement-breakpoint
ALTER TABLE "audit_records" ADD COLUMN "seq" integer;--> statement-breakpoint
ALTER TABLE "audit_records" ADD COLUMN "prev_hash" text;--> statement-breakpoint
ALTER TABLE "audit_records" ADD COLUMN "payload" text;--> statement-breakpoint
ALTER TABLE "audit_records" ADD COLUMN "payload_hash" text;--> statement-breakpoint
ALTER TABLE "audit_records" ADD COLUMN "hash" text;--> statement-breakpoint
ALTER TABLE "audit_records" ADD CONSTRAINT "audit_records_seq_unique" UNIQUE("seq");--> statement-breakpoint
ALTER TABLE "audit_records" ADD CONSTRAINT "audit_records_prev_hash_unique" UNIQUE("prev_hash");