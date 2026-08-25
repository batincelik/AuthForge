import { expect, test } from "@playwright/test";

test("administrator login renders real backend security state", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Email").fill(process.env.AUTHFORGE_E2E_ADMIN_EMAIL ?? "instance-admin@example.com");
  await page.getByLabel("Password").fill(process.env.AUTHFORGE_E2E_ADMIN_PASSWORD ?? "a genuinely long admin passphrase");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole("heading", { name: "Security console" })).toBeVisible();
  await expect(page.getByText("instance-admin@example.com", { exact: false }).first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Security events" })).toBeVisible();
});
