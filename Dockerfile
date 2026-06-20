# ShellWard 公开仓库 web 扫描器 —— 一键部署到任意容器平台
# build: docker build -t shellward-web .
# run:   docker run -p 8080:8080 shellward-web
# 平台(Render/Railway/Fly/自建)通常会注入 $PORT，下面已兼容。

FROM node:20-alpine
RUN apk add --no-cache git
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev || npm install

COPY . .
RUN npm run build

ENV PORT=8080
ENV SHELLWARD_LOCALE=zh
EXPOSE 8080

# 公网模式：贴公开仓库 URL 体检（私有代码请用本地 CLI: npx shellward scan）
CMD ["sh", "-c", "node dist/cli.js web ${PORT}"]
