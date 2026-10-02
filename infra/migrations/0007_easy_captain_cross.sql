ALTER TABLE "audit_records" ALTER COLUMN "agent_did" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "audit_records" ALTER COLUMN "tool" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "audit_records" ADD COLUMN "principal_kind" text;--> statement-breakpoint
ALTER TABLE "audit_records" ADD COLUMN "principal_id" text;--> statement-breakpoint
ALTER TABLE "audit_records" ADD COLUMN "principal_name" text;