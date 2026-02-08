export interface ApiError {
  code: number;
  message: string;
  attachment: string | null;
}

export interface ApiResponse<T = any> {
  date: number;
  success: boolean;
  data: T | null;
  error: ApiError | null;
}
