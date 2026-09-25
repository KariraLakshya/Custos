ALTER TABLE "agents" ALTER COLUMN "key_id" DROP NOT NULL;--> statement-breakpoint
ALTER TABLE "agents" ADD COLUMN "public_key_multibase" text;--> statement-breakpoint
ALTER TABLE "agents" ADD CONSTRAINT "agents_public_key_multibase_unique" UNIQUE("public_key_multibase");