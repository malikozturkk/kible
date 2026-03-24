-- CreateTable
CREATE TABLE "questions" (
    "id" TEXT NOT NULL,
    "guideId" TEXT NOT NULL,
    "question" TEXT NOT NULL,
    "options" TEXT[] NOT NULL,
    "correctAnswer" TEXT NOT NULL,
    "difficulty" INTEGER,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "questions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "questions_guideId_idx" ON "questions"("guideId");
