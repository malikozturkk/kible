import {
  PAGINATION_DEFAULT_PAGE_SIZE,
  PAGINATION_MAX_PAGE_SIZE,
  PaginationDto,
} from '../dto/pagination.dto';

export interface PageMeta {
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  hasNextPage: boolean;
}

export interface Paginated<T> {
  items: T[];
  meta: PageMeta;
}

export function paginate(pagination: PaginationDto = {}): {
  skip: number;
  take: number;
  page: number;
  pageSize: number;
} {
  const page = Math.max(pagination.page ?? 1, 1);
  const pageSize = Math.min(
    Math.max(pagination.pageSize ?? PAGINATION_DEFAULT_PAGE_SIZE, 1),
    PAGINATION_MAX_PAGE_SIZE,
  );

  return { skip: (page - 1) * pageSize, take: pageSize, page, pageSize };
}

export function buildPageMeta(page: number, pageSize: number, total: number): PageMeta {
  const totalPages = Math.max(Math.ceil(total / pageSize), 1);
  return { page, pageSize, total, totalPages, hasNextPage: page < totalPages };
}
