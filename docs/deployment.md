# Deployment Guide: Vercel & Render

This guide explains how to deploy TrustLens to production with **Vercel** (frontend) and **Render** (backend).

---

## 1. Frontend Deployment (Vercel)

The frontend is a Vite + React + TypeScript + Tailwind CSS application located in the `frontend/` directory.

### Step-by-Step Instructions

1. **Sign In:**
   - Go to [vercel.com](https://vercel.com) and log in with your GitHub account.

2. **Import Repository:**
   - Click **"Add New..."** → **"Project"**.
   - Select the repository: `MdAsif678/Hackmatrix_Breaking_Bugs`.

3. **Configure Project Settings (CRITICAL):**
   - **Framework Preset:** `Vite` (auto-detected).
   - **Root Directory:** Click **Edit** and set to `frontend` (do not leave as root `/`).
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`

4. **Environment Variables:**
   - Add the following variable:
     - **Key:** `VITE_API_URL`
     - **Value:** Your live backend URL followed by `/api` (e.g. `https://trustlens-api.onrender.com/api`).
     - *(If the backend is not yet deployed, leave it empty for now; Vite will default to relative `/api`).*

5. **Deploy:**
   - Click **Deploy**. Vercel will build the frontend and generate a live URL (e.g. `https://trustlens-app.vercel.app`).
   - SPA route rewrites are pre-configured in [`frontend/vercel.json`](../frontend/vercel.json) to handle direct links and page refreshes.

---

## 2. Backend Deployment (Render)

The backend is a FastAPI Python 3.11+ application located in `backend/`.

### Step-by-Step Instructions

1. **Sign In:**
   - Go to [render.com](https://render.com) and sign in with GitHub.

2. **Create Web Service:**
   - Click **New +** → **Web Service**.
   - Connect the repository `MdAsif678/Hackmatrix_Breaking_Bugs`.

3. **Configure Service:**
   - **Name:** `trustlens-api`
   - **Region:** Closest to your users (e.g. Singapore or Frankfurt).
   - **Root Directory:** `backend`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Plan:** Free tier

4. **Environment Variables on Render:**
   Under **Environment Variables**, add the secrets from your `.env`:
   - `LLM_PROVIDER`: `gemini`
   - `LLM_API_KEY`: *(Your Google Gemini API Key)*
   - `LLM_MODEL`: leave **empty** (the backend tries `gemini-flash-lite-latest`, then `gemini-3.5-flash`, then
     `gemini-flash-latest`). Do not use `gemini-1.5-flash` or `gemini-2.5-flash`: Google has retired them.
   - `GOOGLE_SAFE_BROWSING_API_KEY`: *(Google Safe Browsing key)*
   - `URLHAUS_AUTH_KEY`: *(URLhaus Auth-Key)*
   - `CORS_ORIGINS`: your Vercel URL, e.g. `https://trustlens-app.vercel.app` (comma-separated for several).
     **Required:** without it the browser blocks every call from the live site to the API.
   - `SEPOLIA_RPC_URL`: *(Your Sepolia RPC provider URL)*
   - `REGISTRY_CONTRACT_ADDRESS`: *(Sepolia contract address)*
   - `REGISTRY_PRIVATE_KEY`: *(Throwaway wallet private key)*
   - `CHECK_TIMEOUT_SECONDS`: `8`
   - `MOCK_ANALYZERS`: `false`

5. **Connect to Vercel:**
   - Copy the Render web service URL (e.g. `https://trustlens-api.onrender.com`).
   - In Vercel, go to **Settings** → **Environment Variables** → update `VITE_API_URL` to `https://trustlens-api.onrender.com/api`.
   - Trigger a redeployment on Vercel.
   - In Render, set `CORS_ORIGINS` to the Vercel URL (step 4) and redeploy the backend.

---

## 3. Things to know before the demo

- **Free Render instances sleep after about 15 minutes idle.** The first check after that waits 30-60 seconds while
  it wakes. Open `https://<your-api>.onrender.com/api/health` a minute before presenting.
- **The database is a SQLite file on Render's disk, which is wiped on every redeploy** (history, links between
  reports and sealed reports start empty). Do not redeploy between sealing a report and showing it.
- **Blockchain:** the local Hardhat chain only runs on a laptop. The live site needs P4's Sepolia deployment
  (`SEPOLIA_RPC_URL`, `REGISTRY_CONTRACT_ADDRESS`, `REGISTRY_PRIVATE_KEY`); until then "Seal this report" explains
  what is missing.
- **`VITE_API_URL` must be set on Vercel.** If it is empty, `vercel.json` sends `/api/...` to `index.html` and every
  check fails.
- **Python:** set `PYTHON_VERSION=3.11.9` on Render to match the version the project is tested on.
- Never commit `.env`; paste secrets into the Vercel and Render dashboards only.
