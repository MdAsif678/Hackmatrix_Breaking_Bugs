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
   - `LLM_MODEL`: `gemini-1.5-flash`
   - `SEPOLIA_RPC_URL`: *(Your Sepolia RPC provider URL)*
   - `REGISTRY_CONTRACT_ADDRESS`: *(Sepolia contract address)*
   - `REGISTRY_PRIVATE_KEY`: *(Throwaway wallet private key)*
   - `CHECK_TIMEOUT_SECONDS`: `8`
   - `MOCK_ANALYZERS`: `false`

5. **Connect to Vercel:**
   - Copy the Render web service URL (e.g. `https://trustlens-api.onrender.com`).
   - In Vercel, go to **Settings** → **Environment Variables** → update `VITE_API_URL` to `https://trustlens-api.onrender.com/api`.
   - Trigger a redeployment on Vercel.
